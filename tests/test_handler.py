import io
import pytest
import janus
import asyncio
# from dns.resolver import Resolver

from typing import Any, List
from handler import resolve_dns_name, \
                    resolve_dns_name_blocking, \
                    check_if_ip_in_subnet, \
                    return_domain_metrics, \
                    read_file_to_list, \
                    normalize_domains, \
                    fill_queue


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
    ips_list = ['192.168.10.1', '192.168.17.100', '8.8.8.8']
    blocked_subnets_set = {'192.168.0.0/20', '10.0.0.0/8'}
    domain_metrics = return_domain_metrics(dns_name=fake_dns_name,
                                           ips_list=ips_list,
                                           blocked_subnets_set=blocked_subnets_set)
    assert domain_metrics == f'rkn_resolved_ip_count{{domain_name="{fake_dns_name}"}} 3\nrkn_resolved_ip_blocked_count{{domain_name="{fake_dns_name}"}} 1\n'


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


def test_normalize_domains_set():
    domains_list = [
        'mail.ru',
        'mail.ru',
        'google.com domain',
        'google.com',
        'just any string'
    ]
    domains_set = normalize_domains(domains_list=domains_list)
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
