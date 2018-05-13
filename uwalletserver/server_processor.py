import Queue

from uwalletserver.processor import Processor
from uwalletserver import __version__ as VERSION


class ServerProcessor(Processor):
    def __init__(self, config, shared,stroage):
        Processor.__init__(self)
        self.storage = stroage
        self.daemon = True
        self.config = config
        self.shared = shared
        self.irc_queue = Queue.Queue()
        self.peers = {}
        self.irc = None

    def get_peers(self):
        return self.peers.values()

    def process(self, request):
        method = request['method']
        params = request['params']
        result = None

        if method == 'server.banner':
            result = self.storage.height

        elif method == 'server.donation_address':
            result = self.config.get('server', 'donation_address')

        elif method == 'server.peers.subscribe':
            result = self.get_peers()

        elif method == 'server.version':
            result = VERSION

        else:
            raise BaseException("unknown method: %s" % repr(method))

        return result
