import os
import argparse
import asyncio
import logging

from aiohttp import web
from concurrent.futures import ThreadPoolExecutor
from handler import resolve_dns_name, \
                    return_domain_metrics

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
    parser.add_argument('-f', '--file',
                        default=os.getenv("APP_FILE_PATH", ''),
                        type=str,
                        help='Absolute path to file. Each line is url link (default: Empty string)')
    return parser.parse_args()


class Component:
    def __init__(self,
                 name="rkn-exporter",
                 loop=asyncio.get_event_loop()):
        self.name = name
        self.loop = loop
        self.io_pool_exc = ThreadPoolExecutor(max_workers=10)

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
        while True:
            blocked_subnets_list = ['192.168.0.0/20', '94.100.0.0/16']
            dns_name = 'mail.ru'
            data = return_domain_metrics(dns_name=dns_name,
                                         ips_list= await resolve_dns_name(dns_name),
                                         blocked_subnets_list=blocked_subnets_list)

            # you don't need to set loop explicitly in avaitable objects because of deprecation warning:
            #   DeprecationWarning: The loop argument is deprecated since
            #   Python 3.8,and scheduled for removal in Python 3.10.
            #
            # Read more at: https://stackoverflow.com/a/60315290
            await asyncio.sleep(60)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    component = Component(loop=loop)
    loop.run_until_complete(component.start())

    requestor = Requestor(loop=loop)
    loop.run_until_complete(requestor.handler())

    loop.run_forever()
