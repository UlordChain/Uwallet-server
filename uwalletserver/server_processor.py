import Queue

from uwalletserver.processor import Processor
from uwalletserver import __version__ as VERSION
from uwalletserver.blockchain_processor import BLOCKS_PER_CHUNK

class ServerProcessor(Processor):
    def __init__(self, config, shared,storage):
        Processor.__init__(self)
        self.storage = storage
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
            try:
                result = "2.7.2,"+ str(BLOCKS_PER_CHUNK)
            except Exception,ex:
                print ex
                return 0

        elif method == 'server.donation_address':
            result = self.config.get('server', 'donation_address')

        elif method == 'server.peers.subscribe':
            result = self.get_peers()

        elif method == 'server.version':
            result = VERSION

        else:
            raise BaseException("unknown method: %s" % repr(method))

        return result
