
import time

def profile(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()

        # print(dir(method))
        print('%30r %2.6f sec' % (method.__class__.__name__ + "." + method.__name__, te-ts))
        return result
    return timed

from lwd.main import main
