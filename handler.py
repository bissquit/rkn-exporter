import os
import re
import time
import json
import aiodns
import aiohttp
import asyncio
import janus
import logging
import ipaddress
import threading
import validators
from dns.resolver import Resolver
from dns.exception import DNSException


logging.basicConfig(level=os.getenv("LOG_LEVEL", logging.DEBUG),
                    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)


# async def resolve_dns_name(dns_name):
#     hosts_list = []
#     async with aiodns.DNSResolver(loop=asyncio.get_event_loop()) as resolver:
#         try:
#             async with resolver.query(host=dns_name, ) as response:
#                 # create a list of ip addresses
#                 for item in response:
#                     hosts_list.append(item.host)
#         except aiodns.error.DNSError as error:
#             logger.warning(f'Error during resolving: {error}')
#     return hosts_list


async def resolve_dns_name(dns_name: str) -> list[str]:
    hosts_list = []

    resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
    try:
        response = await resolver.query(host=dns_name, qtype='A')
        for item in response:
            hosts_list.append(item.host)
    except aiodns.error.DNSError as error:
        logger.warning(f'Error resolving DNS name: {error}')

    return hosts_list


def resolve_dns_name_blocking(dns_name: str, resolver: Resolver) -> tuple[list, int]:
    hosts_list = []
    resolving_errors_count = 0

    try:
        response = resolver.resolve(dns_name, 'A')
        for item in response:
            hosts_list.append(item.to_text())
    except DNSException as error:
        logger.warning(f'Error resolving DNS name: {error}')
        resolving_errors_count = 1

    return hosts_list, resolving_errors_count


def check_if_ip_in_subnet(ip, subnet, dns_name) -> bool:
    ip_in_subnet = False
    if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
        ip_in_subnet = True
    return ip_in_subnet


def read_file_to_list(path: str) -> list:
    file_data_list = []
    try:
        with open(path, 'r') as file:
            for line in file.readlines():
                # rstrip() removes any types of trailing whitespace
                # including spaces, newlines etc.
                file_data_list.append(line.rstrip())
    except OSError as error:
        logger.error(f'Could not open file {path}. Error: {error}')
        # possibly we need to trigger sys.exit here
        # I'll do it later
    return file_data_list


def subnet_to_ips(subnet: str) -> set:
    set_of_ips = set()
    for ip in ipaddress.ip_network(subnet):
        set_of_ips.add(str(ip))
    return set_of_ips


def subnets_to_ips(subnets_set: set) -> set:
    full_set_of_ips = set()
    for subnet in subnets_set:
        for ip in subnet_to_ips(subnet=subnet):
            full_set_of_ips.add(ip)
    logger.info(f'{len(full_set_of_ips)} blocked ip addresses discovered')
    return full_set_of_ips


def is_valid_domain(domain_name: str) -> bool:
    is_valid = False
    regex = "^((?!-)[_A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}\\.?$"
    p = re.compile(regex)

    if domain_name != '':
        if re.search(p, domain_name):
            is_valid = True
    return is_valid


def validate_domains(domains_list: list) -> set:
    valid_domains_set = set()
    invalid_domains = duplicated_domains = 0

    for domain_name in domains_list:
        # the best idea is to use validators.domain(domain_name)
        # but this function handle underscore as invalid character
        # in domain naming. That is why we use simple regex
        #
        # check if line is a valid domain
        if is_valid_domain(domain_name=domain_name):
            # check duplicated domains ...
            if domain_name in valid_domains_set:
                logger.debug(f'{domain_name} domain is already exist')
                duplicated_domains += 1
            # ... because set().add() method doesn't raise
            # error if item is already exist in a set
            valid_domains_set.add(domain_name)
        else:
            logger.debug(f'This line is not a valid domain: {domain_name}')
            invalid_domains += 1

    if invalid_domains:
        logger.warning(f'{invalid_domains} invalid domain(s) discovered! Check input file')
    if duplicated_domains:
        logger.warning(f'{duplicated_domains} duplicated domain(s) found')
    logger.info(f'{len(valid_domains_set)} domains discovered')
    return valid_domains_set


def return_domain_metrics(dns_name: str, ips_list: list, blocked_ips_set: set) -> str:
    blocked_ip_count = 0
    metrics_str = ''

    if ips_list:
        for ip in ips_list:
            if ip in blocked_ips_set:
                blocked_ip_count += 1
        metrics_str = f'rkn_resolved_ip_count{{domain_name="{dns_name}"}} {len(ips_list)}\n'
        metrics_str += f'rkn_resolved_ip_blocked_count{{domain_name="{dns_name}"}} {blocked_ip_count}\n'
        metrics_str += f'rkn_resolved_success{{domain_name="{dns_name}"}} 1\n'
    else:
        metrics_str += f'rkn_resolved_success{{domain_name="{dns_name}"}} 0\n'

    return metrics_str


def time_diff(time_old: float) -> float:
    return round(time.time() - time_old, 5)


def return_metrics(domains_set_queue: janus.Queue, blocked_ips_set: set, resolver: Resolver) -> str:
    # check in what thread we are
    thread_id = threading.get_ident()
    logger.debug(f'Thread id: {thread_id}; Starting thread...')

    metrics = ''
    domains_count = resolving_errors_count = 0
    time_start = time.time()

    while domains_set_queue.sync_q.qsize() != 0:
        logger.debug(f'Thread id: {thread_id}; Current queue size is {domains_set_queue.sync_q.qsize()} element(s)')
        # a fact that queue is not empty is checked above in while loop
        # condition but we should handle Queue.sync_q.get() event because
        # if the queue had the last item it might be retrieved from another
        # thread between .qsize() and .get() events in the current thread
        try:
            time_queue = time.time()
            dns_name = domains_set_queue.sync_q.get(block=False)
            logger.debug(f'Thread id: {thread_id}; Domain {dns_name} retrieved from the queue in {time_diff(time_queue)}s')

            time_resolving = time.time()
            domains_count += 1
            ips_list, errors = resolve_dns_name_blocking(dns_name, resolver)
            resolving_errors_count += errors
            logger.debug(f'Thread id: {thread_id}; Domain {dns_name} resolved in {time_diff(time_resolving)}s')

            time_subnets = time.time()
            metrics += return_domain_metrics(dns_name=dns_name,
                                             ips_list=ips_list,
                                             blocked_ips_set=blocked_ips_set)
            logger.debug(f'Thread id: {thread_id}; Checked if ip address(es) of domain {dns_name} are blocked in {time_diff(time_subnets)}s')
            domains_set_queue.sync_q.task_done()
        # empty exception
        except janus.SyncQueueEmpty as _:
            logger.debug(f'Thread id: {thread_id}; Queue is empty because the last element was retrieved from another thread')
    logger.info(f'Thread id: {thread_id}; Thread is finished after {time_diff(time_start)}s. {domains_count} domains processed. {resolving_errors_count} resolving errors')
    return metrics


def fill_queue(queue: janus.Queue[str], domains_set: set) -> None:
    sync_q = queue.sync_q
    if sync_q.qsize() == 0:
        logger.debug(f'Starting filling a queue')
        for item in domains_set:
            sync_q.put(item=item)
        logger.debug(f'Queue filling is finished')
    else:
        logger.error(f'Queue is not empty! Queue with max size {sync_q.maxsize} already has {sync_q.qsize()} element(s)')


async def get_data(url: str) -> json:
    # json.loads() requires str beginning with a JSON document
    json_body = json.loads('{}')

    async with aiohttp.ClientSession() as client:
        try:
            async with client.get(url) as r:
                status = r.status
                logger.info(f'Requesting url {url}')
                logger.debug(f'Full response: {r}')
                if status == 200:
                    json_body = await r.json()
                else:
                    logger.error(f'Cannot request url {url}! Response status: {status}')
        except aiohttp.ClientError as error:
            logger.error(f'Connection error to url {url}: {error}')

    return json_body


def ip_converter(subnets_list: list) -> set:
    """Input list may include both ipv4/ipv6 or network subnets. One item per line"""
    blocked_subnets_set = set()
    invalid_string_counter = 0
    invalid_strings_list = []

    for item in subnets_list:
        if validators.ipv6(item):
            # ipv6 is not supported yet
            pass
        elif validators.ipv4(item):
            # convert ipv4 to subnet
            ipv4_network = str(ipaddress.ip_network(item))
            blocked_subnets_set.add(ipv4_network)
        elif validators.ipv4_cidr(item):
            blocked_subnets_set.add(item)
        else:
            logger.debug(f'This string is neither IPv4/IPv6 address nor IP subnet: {item}')
            invalid_string_counter += 1
            invalid_strings_list.append(item)

    logger.info(f'{len(blocked_subnets_set)} subnets in blocked subnets list')
    if invalid_string_counter:
        logger.warning(f'{invalid_string_counter} invalid strings were discovered during input list analyzing')
        logger.debug(f'Here a full list of all invalid strings of IPv4/IPv6/subnet: {invalid_strings_list}')
    return blocked_subnets_set


async def data_handler(path: str) -> set:
    """check what is path - a valid url or path to a file"""
    if validators.url(path):
        logger.info(f'Trying to access url {path} to retrieve blocked subnets list')
        raw_data = await get_data(url=path)
        # blocked_subnets_set = set(ip_converter(raw_data))
    else:
        logger.info(f'Trying to access file {path} to retrieve blocked subnets list')
        raw_data = read_file_to_list(path=path)

    return set(ip_converter(raw_data))
