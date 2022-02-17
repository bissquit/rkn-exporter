import pytest

from typing import Any, List
from handler import resolve_dns_name, \
                    check_if_ip_in_subnet, \
                    return_domain_metrics


# taken from https://github.com/aio-libs/aiohttp/blob/master/tests/test_resolver.py
class FakeQueryResult:
    host: Any

    def __init__(self, host: Any) -> None:
        self.host = host


async def fake_query_result(result: Any) -> List[FakeQueryResult]:
    return [FakeQueryResult(host=h) for h in result]


@pytest.mark.asyncio
async def test_resolve_dns_name(mocker):
    fake_dns_name = 'domain.tld'

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
    fake_dns_name = 'domain.tld'
    ip, subnet = '192.168.10.1', '192.168.0.0/23'
    ip_in_subnet = check_if_ip_in_subnet(ip=ip, subnet=subnet, dns_name=fake_dns_name)
    assert  ip_in_subnet is False

    ip, subnet = '192.168.10.1', '192.168.0.0/20'
    ip_in_subnet = check_if_ip_in_subnet(ip=ip, subnet=subnet, dns_name=fake_dns_name)
    assert ip_in_subnet is True


def test_return_domain_metrics():
    fake_dns_name = 'domain.tld'

    ips_list = ['192.168.10.1', '192.168.17.100', '8.8.8.8']
    blocked_subnets_list = ['192.168.0.0/20', '10.0.0.0/8']
    domain_metrics = return_domain_metrics(dns_name=fake_dns_name,
                                           ips_list=ips_list,
                                           blocked_subnets_list=blocked_subnets_list)
    assert domain_metrics == f'rkn_resolved_ip_count{{domain_name="{fake_dns_name}"}} 3\nrkn_resolved_ip_blocked_count{{domain_name="{fake_dns_name}"}} 1\n'
