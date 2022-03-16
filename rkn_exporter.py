import os
import argparse
import asyncio
import logging
import janus

from aiohttp import web
from concurrent.futures import ThreadPoolExecutor
from dns.resolver import Resolver
from handler import \
    read_file_to_list, \
    validate_domains, \
    return_metrics, \
    fill_queue, \
    subnets_to_ips, \
    data_handler

# possibly it's good idea to use contextvars here
data = 'rkn_computation_success 0'

logging.basicConfig(level=os.getenv("LOG_LEVEL", logging.DEBUG),
                    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)


def parse_args():
    # You may either use command line argument or env variables
    parser = argparse.ArgumentParser(prog='rkn_exporter',
                                     description='''Prometheus exporter developed to indicate what your domains
                                                    are blocked by Roskomnadzor agency to access from Russia''')
    parser.add_argument('-i', '--ip',
                        default=os.getenv("APP_IP", '0.0.0.0'),
                        type=str,
                        help='IP address (default: 0.0.0.0)')
    parser.add_argument('-p', '--port',
                        default=os.getenv("APP_PORT", 8080),
                        type=int,
                        help='Port to be listened (default: 8080)')
    parser.add_argument('-c', '--check_interval',
                        default=os.getenv("APP_CHECK_INTERVAL", 3600),
                        type=int,
                        help='Default time range in seconds to check metrics (default: 60)')
    parser.add_argument('-d', '--domains',
                        default=os.getenv("APP_DOMAINS"),
                        type=str,
                        help='Path to a file with domains to check. One domain per line (default: No)')
    parser.add_argument('-s', '--blocked_subnets',
                        default=os.getenv("APP_SUBNETS"),
                        type=str,
                        help='Path to a file with subnets bloked by RKN. One subnet per line. Or url with json list (default: No)')
    parser.add_argument('-t', '--threads_count',
                        default=os.getenv("APP_THREADS", 10),
                        type=int,
                        help='Threads count to parallelize computation. Is useful when DNS resolving is slow (default: 10)')
    return parser.parse_args()


class Component:
    def __init__(self,
                 name="rkn-exporter",
                 loop=asyncio.get_event_loop(),
                 args=None):
        self.name = name
        self.loop = loop
        self.args = args

    async def start(self):
        app = web.Application()
        # For storing global-like variables, feel free to save them in an Application instance
        runner = web.AppRunner(app)
        app.router.add_get('/metrics', self.handle_work)

        await runner.setup()
        site = web.TCPSite(runner, self.args.ip, self.args.port)
        await site.start()

    async def handle_work(self, request):
        global data
        return web.Response(text=data)


class Requestor:
    def __init__(self,
                 loop=asyncio.get_event_loop(),
                 args=None):
        self.loop = loop
        self.args = args

    async def handler(self):
        global data
        threads_count = self.args.threads_count
        domains_file_path = self.args.domains

        logger.info(f'Looking for domains in file {domains_file_path}')
        domains_set = validate_domains(read_file_to_list(domains_file_path))

        blocked_subnets_set = await data_handler(self.args.blocked_subnets)
        blocked_ips_set = subnets_to_ips(blocked_subnets_set)

        # I'll add variables later
        resolver = self.initialize_resolver(nameservers=['8.8.8.8'],
                                            timeout=20,
                                            lifetime=20,
                                            retry_servfail=False)
        queue = janus.Queue(maxsize=len(domains_set))

        while True:
            # fast but blocking function
            fill_queue(queue=queue, domains_set=domains_set)

            logger.info(f'Starting resolving in {threads_count} thread(s)')
            executor = ThreadPoolExecutor(max_workers=threads_count)
            # you should pass blocking function into executor or start additional
            # event loop inside that function each time it called if you want async behaviour
            futures = [
                self.loop.run_in_executor(executor, return_metrics, queue, blocked_ips_set, resolver)
                for _ in range(threads_count)
            ]
            raw_data = await asyncio.gather(*futures)
            logger.info(f'Resolving is finished')
            data = ''.join(raw_data)
            data += 'rkn_computation_success 1\n'

            # you don't need to set loop explicitly in awaitable objects otherwise you'll get deprecation warning:
            #   DeprecationWarning: The loop argument is deprecated since
            #   Python 3.8, and scheduled for removal in Python 3.10.
            #
            # Read more at: https://stackoverflow.com/a/60315290
            await asyncio.sleep(self.args.check_interval)

    @staticmethod
    def initialize_resolver(nameservers: list,
                            timeout: int,
                            lifetime: int,
                            retry_servfail: bool) -> Resolver:
        resolver = Resolver()
        resolver.nameservers = nameservers
        resolver.timeout = timeout
        # don't set lifetime less than 20s because of
        # "The resolution lifetime expired" error for some domains
        resolver.lifetime = lifetime
        resolver.retry_servfail = retry_servfail
        return resolver


if __name__ == '__main__':
    args = parse_args()
    loop = asyncio.get_event_loop()

    component = Component(loop=loop, args=args)
    loop.run_until_complete(component.start())

    requestor = Requestor(loop=loop, args=args)
    loop.run_until_complete(requestor.handler())

    loop.run_forever()
