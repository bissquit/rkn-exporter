import os
import argparse
import asyncio
import logging
import janus

from aiohttp import web
from concurrent.futures import ThreadPoolExecutor
from handler import read_file_to_list, \
                    normalize_domains, \
                    return_metrics, initialize_resolver, fill_queue

# possibly it's good idea to use contextvars here
data = ''

logging.basicConfig(level=os.getenv("LOG_LEVEL", logging.DEBUG),
                    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)


def parse_args():
    # You may either use command line argument or env variables
    parser = argparse.ArgumentParser(prog='rkn_exporter',
                                     description='''Prometheus exporter developed to indicate what your domains
                                                    are blocked by Roskomnadzor agency to access from Russia''')
    parser.add_argument('-p', '--port',
                        default=os.getenv("APP_PORT", 8080),
                        type=int,
                        help='Port to be listened (default: 8080)')
    parser.add_argument('-t', '--time',
                        default=os.getenv("APP_CHECK_INTERVAL", 60),
                        type=int,
                        help='Default time range in seconds to check metrics (default: 60)')
    return parser.parse_args()


class Component:
    def __init__(self,
                 name="rkn-exporter",
                 loop=asyncio.get_event_loop()):
        self.name = name
        self.loop = loop

    async def start(self):
        # Server
        args = parse_args()
        app = web.Application()
        # For storing global-like variables, feel free to save them in an Application instance
        app['args'] = args
        runner = web.AppRunner(app)
        app.router.add_get('/metrics', self.handle_work)

        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 8080)
        await site.start()

    async def handle_work(self, request):
        global data
        return web.Response(text=data)


class Requestor:
    def __init__(self, loop=asyncio.get_event_loop()):
        self.loop = loop

    async def handler(self):
        global data
        domains_set = normalize_domains(read_file_to_list('/app/inputs/domains.txt'))
        blocked_subnets_set = set(read_file_to_list('/app/inputs/blocked_subnets.txt'))
        resolver = initialize_resolver()
        queue = janus.Queue(maxsize=len(domains_set))

        while True:
            # fast but blocking function
            fill_queue(queue=queue, domains_set=domains_set)

            threads_count = 2
            executor = ThreadPoolExecutor(max_workers=threads_count)
            # you should pass blocking function into executor or start additional
            # event loop inside that function each time it called if you want async behaviour
            futures = [
                self.loop.run_in_executor(executor, return_metrics, queue, blocked_subnets_set, resolver)
                for _ in range(threads_count)
            ]
            raw_data = await asyncio.gather(*futures)
            data = ''.join(raw_data)

            # you don't need to set loop explicitly in awaitable objects otherwise you'll get deprecation warning:
            #   DeprecationWarning: The loop argument is deprecated since
            #   Python 3.8, and scheduled for removal in Python 3.10.
            #
            # Read more at: https://stackoverflow.com/a/60315290
            await asyncio.sleep(3600)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    component = Component(loop=loop)
    loop.run_until_complete(component.start())

    requestor = Requestor(loop=loop)
    loop.run_until_complete(requestor.handler())

    loop.run_forever()
