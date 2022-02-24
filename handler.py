import os
import re
import time
import aiodns
import asyncio
import janus
import logging
import ipaddress
import threading
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


async def resolve_dns_name(dns_name) -> list[str]:
    hosts_list = []

    resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
    try:
        response = await resolver.query(host=dns_name, qtype='A')
        for item in response:
            hosts_list.append(item.host)
    except aiodns.error.DNSError as error:
        logger.warning(f'Error resolving DNS name: {error}')

    return hosts_list


def initialize_resolver() -> Resolver:
    resolver = Resolver()
    resolver.nameservers = ['8.8.8.8']
    resolver.timeout = 20
    # don't set lifetime less than 20s because of
    # "The resolution lifetime expired" error for some domains
    resolver.lifetime = 20
    resolver.retry_servfail = False
    return resolver


def resolve_dns_name_blocking(dns_name: str, resolver: Resolver) -> tuple[list, int]:
    hosts_list = []
    resolving_errors_count = 0

    try:
        response = resolver.resolve(dns_name, 'A')
        for item in response:
            hosts_list.append(item.to_text())
    except DNSException as error:
        logger.warning(f'Error resolving DNS name: {error}')
        resolving_errors_count += 1

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
    return full_set_of_ips


def is_valid_domain(domain_name) -> bool:
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
        logger.warning(f'{duplicated_domains} duplicated domain(s) found in input file')
    return valid_domains_set


def return_domain_metrics(dns_name: str, ips_list: list, blocked_ips_set: set) -> str:
    blocked_ip_count = 0
    for ip in ips_list:
        if ip in blocked_ips_set:
            blocked_ip_count += 1

    metrics_str = f'rkn_resolved_ip_count{{domain_name="{dns_name}"}} {len(ips_list)}\n'
    metrics_str += f'rkn_resolved_ip_blocked_count{{domain_name="{dns_name}"}} {blocked_ip_count}\n'
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
            queue_item = domains_set_queue.sync_q.get(block=False)
            logger.debug(f'Thread id: {thread_id}; Domain {queue_item} retrieved from the queue in {time_diff(time_queue)}s')

            time_resolving = time.time()
            domains_count += 1
            ips_list, errors = resolve_dns_name_blocking(queue_item, resolver)
            resolving_errors_count += errors
            logger.debug(f'Thread id: {thread_id}; Domain {queue_item} resolved in {time_diff(time_resolving)}s')

            if ips_list:
                time_subnets = time.time()
                metrics += return_domain_metrics(dns_name=queue_item,
                                                 ips_list=ips_list,
                                                 blocked_ips_set=blocked_ips_set)
                logger.debug(f'Thread id: {thread_id}; Checked if ip address(es) of domain {queue_item} are blocked in {time_diff(time_subnets)}s')

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
