import io
import json
import yarl
import pytest
import janus
import asyncio
import aiohttp
import ipaddress
from dns.resolver import Resolver
from multidict import CIMultiDictProxy, CIMultiDict
# from dns.resolver import Resolver

from typing import Any, List
from handler import resolve_dns_name, \
                    resolve_dns_name_blocking, \
                    check_if_ip_in_subnet, \
                    return_domain_metrics, \
                    read_file_to_list, \
                    validate_domains, \
                    fill_queue, subnet_to_ips, subnets_to_ips, get_data, ip_converter, data_handler, normalize_dns


# taken from https://github.com/aio-libs/aiohttp/blob/master/tests/test_resolver.py
class FakeQueryResult:
    host: Any

    def __init__(self, host: Any) -> None:
        self.host = host


async def fake_query_result(result: Any) -> List[FakeQueryResult]:
    return [FakeQueryResult(host=h) for h in result]


# emulates incorrect directory path
class MockOpenFile:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        raise OSError

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


async def mock_awaitable_obj(data):
    return data


class MockResponse:
    def __init__(self, text, status, error_code=None, headers=None):
        self._text = text
        self.status = status
        self.error_code = error_code
        self.headers = headers

    async def __aexit__(self, exc_type, exc, tb):
        pass

    async def __aenter__(self):
        # MultiDictProxy - HTTP Headers and URL query string require specific data structure: multidict.
        # It behaves mostly like a dict but may have several values for the same key.
        #
        # CIMultiDictProxy - Case insensitive version of MultiDictProxy
        # https://docs.aiohttp.org/en/v0.14.4/multidict.html
        headers = CIMultiDictProxy(CIMultiDict())
        # RequestInfo - a data class with request URL and headers from ClientRequest object,
        # available as ClientResponse.request_info attribute.
        # https://docs.aiohttp.org/en/stable/client_reference.html#requestinfo
        #
        # yarl.URL Represents URL as:
        # [scheme:]//[user[:password]@]host[:port][/path][?query][#fragment]
        # https://yarl.readthedocs.io/en/stable/api.html#yarl.URL
        request_info = aiohttp.RequestInfo(yarl.URL(),
                                           'GET',
                                           headers=headers)
        # based on https://docs.aiohttp.org/en/stable/client_reference.html#hierarchy-of-exceptions
        if self.error_code == 1:
            raise aiohttp.ClientResponseError(request_info, ())
        elif self.error_code == 2:
            raise aiohttp.ClientConnectionError
        elif self.error_code == 3:
            raise aiohttp.ClientPayloadError
        elif self.error_code == 4:
            raise aiohttp.InvalidURL(url='http://fake_url')
        return self

    async def text(self):
        return self._text

    async def json(self):
        return json.loads(self._text)


fake_dns_name = 'domain.tld'


@pytest.mark.asyncio
async def test_resolve_dns_name(mocker):
    mock_resp = fake_query_result(["1.2.3.4"])
    mocker.patch('aiodns.DNSResolver.query', return_value=mock_resp)
    resp = await resolve_dns_name(dns_name=fake_dns_name)
    assert resp == ['1.2.3.4']

    output_list = ["1.2.3.4", "1.2.3.5", "1.2.3.6"]
    mock_resp = fake_query_result(output_list)
    mocker.patch('aiodns.DNSResolver.query', return_value=mock_resp)
    resp = await resolve_dns_name(dns_name=fake_dns_name)
    assert resp == output_list

    output_list = []
    mock_resp = fake_query_result(output_list)
    mocker.patch('aiodns.DNSResolver.query', return_value=mock_resp)
    resp = await resolve_dns_name(dns_name=fake_dns_name)
    assert resp == output_list


def test_check_if_ip_in_subnet():
    ip, subnet = '192.168.10.1', '192.168.0.0/23'
    ip_in_subnet = check_if_ip_in_subnet(ip=ip, subnet=subnet, dns_name=fake_dns_name)
    assert ip_in_subnet is False

    ip, subnet = '192.168.10.1', '192.168.0.0/20'
    ip_in_subnet = check_if_ip_in_subnet(ip=ip, subnet=subnet, dns_name=fake_dns_name)
    assert ip_in_subnet is True


def test_return_domain_metrics():
    blocked_ips_set = {str(ip) for ip in ipaddress.ip_network('192.168.0.0/20')}

    ips_list = ['192.168.10.1', '192.168.17.100', '8.8.8.8']
    domain_metrics = return_domain_metrics(dns_name=fake_dns_name,
                                           ips_list=ips_list,
                                           blocked_ips_set=blocked_ips_set,
                                           ip_in_label=False)
    assert domain_metrics == f'rkn_resolved_ip_count{{domain_name="{fake_dns_name}"}} 3\n' \
                             f'rkn_resolved_ip_blocked_count{{domain_name="{fake_dns_name}"}} 1\n' \
                             f'rkn_resolved_success{{domain_name="{fake_dns_name}"}} 1\n'

    ips_list = ['192.168.10.1', '192.168.17.100', '8.8.8.8']
    domain_metrics = return_domain_metrics(dns_name=fake_dns_name,
                                           ips_list=ips_list,
                                           blocked_ips_set=blocked_ips_set,
                                           ip_in_label=True)
    assert domain_metrics == f'rkn_resolved_ip_blocked{{domain_name="{fake_dns_name}",ip="192.168.10.1"}} 1\n' \
                             f'rkn_resolved_ip_blocked{{domain_name="{fake_dns_name}",ip="192.168.17.100"}} 0\n' \
                             f'rkn_resolved_ip_blocked{{domain_name="{fake_dns_name}",ip="8.8.8.8"}} 0\n' \
                             f'rkn_resolved_ip_count{{domain_name="{fake_dns_name}"}} 3\n' \
                             f'rkn_resolved_ip_blocked_count{{domain_name="{fake_dns_name}"}} 1\n' \
                             f'rkn_resolved_success{{domain_name="{fake_dns_name}"}} 1\n'

    ips_list = []
    domain_metrics = return_domain_metrics(dns_name=fake_dns_name,
                                           ips_list=ips_list,
                                           blocked_ips_set=blocked_ips_set,
                                           ip_in_label=False)
    assert domain_metrics == f'rkn_resolved_ip_count{{domain_name="{fake_dns_name}"}} 0\n' \
                             f'rkn_resolved_ip_blocked_count{{domain_name="{fake_dns_name}"}} 0\n' \
                             f'rkn_resolved_success{{domain_name="{fake_dns_name}"}} 0\n'


@pytest.mark.asyncio
def test_read_file_to_list(mocker):
    file_data_str = 'line\nanother line\n'
    path = '/fake/path'

    # creates file-like obj in memory with appropriate methods like read() and write()
    file = io.StringIO(file_data_str)
    mocker.patch("builtins.open", return_value=file)
    file_data = read_file_to_list(path)
    assert file_data == ['line', 'another line']

    file_obj = MockOpenFile(path=path)
    mocker.patch("builtins.open", return_value=file_obj)
    file_data = read_file_to_list(path)
    assert file_data == []


def test_validate_domains():
    """is_valid_domain also tested here"""
    domains_list = [
        'mail.ru',
        'mail.ru',
        'google.com domain',
        'google.com',
        'just any string'
    ]
    domains_set = validate_domains(domains_list=domains_list)
    assert domains_set == {'mail.ru', 'google.com'}


@pytest.mark.asyncio
async def test_fill_queue():
    domains_set = {'mail.ru', 'google.com'}

    async def coro(queue):
        queue_items = []
        while queue.sync_q.qsize() != 0:
            queue_item = queue.sync_q.get(block=False)
            queue_items.append(queue_item)
        return queue_items

    # configure event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    queue = janus.Queue(maxsize=2)
    queue_with_item = janus.Queue(maxsize=2)

    # put one item to emulate not empty queue
    queue_with_item.sync_q.put(fake_dns_name)

    fill_queue(queue=queue, domains_set=domains_set)
    fill_queue(queue=queue_with_item, domains_set=domains_set)

    result = await asyncio.Task(coro(queue=queue))
    result_with_item = await asyncio.Task(coro(queue=queue_with_item))

    assert domains_set == set(result)
    assert [fake_dns_name] == result_with_item


def test_subnet_to_ips():
    valid_ips_set = set({str(ip) for ip in ipaddress.ip_network('192.168.0.0/28')})
    ips_set = subnet_to_ips('192.168.0.0/28')
    assert valid_ips_set == ips_set

    valid_ips_set = {'192.168.0.1'}
    ips_set = subnet_to_ips('192.168.0.1/32')
    assert valid_ips_set == ips_set


def test_subnets_to_ips():
    valid_full_set_of_ips = set({})
    for subnet in {'192.168.1.0/28', '172.16.50.32/27'}:
        for ip in ipaddress.ip_network(subnet):
            valid_full_set_of_ips.add(str(ip))
    full_set_of_ips = subnets_to_ips({'192.168.1.0/28', '172.16.50.32/27'})
    assert valid_full_set_of_ips == full_set_of_ips


@pytest.mark.asyncio
async def test_get_data(mocker):
    json_data = {"data": "json_data"}
    mock_resp = MockResponse(text=json.dumps(json_data),
                             status=200)
    mocker.patch('aiohttp.ClientSession.get', return_value=mock_resp)
    resp = await get_data(url="http://localhost")
    assert resp == json_data

    mock_resp = MockResponse(text=json.dumps({}),
                             status=503)
    mocker.patch('aiohttp.ClientSession.get', return_value=mock_resp)
    resp = await get_data(url="http://localhost")
    assert resp == {}

    # emulate client errors
    for error in range(1, 5):
        print(error)
        mock_resp = MockResponse(text=json.dumps({}),
                                 status=None,
                                 error_code=error)
        mocker.patch('aiohttp.ClientSession.get', return_value=mock_resp)
        resp = await get_data(url="http://localhost")
        assert resp == {}


def test_ip_converter():
    raw_ips_list = [
        "2606:4700:3033::681c:1ab0",
        "178.62.195.161",
        "104.24.104.128/25",
        "invalid_string",
        "   "
    ]
    ips_set = ip_converter(raw_ips_list)
    assert ips_set == {"178.62.195.161/32", "104.24.104.128/25"}


@pytest.mark.asyncio
async def test_data_handler(mocker):
    raw_ips_list = [
        '2606:4700:3033::681c:1ab0',
        '178.62.195.161',
        '104.24.104.128/25',
        'invalid_string',
        '   '
    ]
    valid_subnets_set = set()
    valid_subnets_set.add('178.62.195.161/32')
    valid_subnets_set.add('104.24.104.128/25')

    mocker.patch('handler.get_data', return_value=await mock_awaitable_obj(raw_ips_list))
    blocked_subnets_set = await data_handler('http://fake-url.tld/fake-path/fake-json')
    assert blocked_subnets_set == valid_subnets_set

    mocker.patch('handler.read_file_to_list', return_value=await mock_awaitable_obj(raw_ips_list))
    blocked_subnets_set = await data_handler('./fake/path/to/file')
    assert blocked_subnets_set == valid_subnets_set


def test_normalize_dns():
    input_str = '  8.8.8.8 ,8.8.4.4,  8.8.1.1111'

    valid_dns_list = normalize_dns(input_str)
    assert valid_dns_list == ['8.8.8.8', '8.8.4.4']
