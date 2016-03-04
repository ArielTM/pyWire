class bigPipe(object):
    def __init__(self , size):
        self._maxSize = size
        self._buffer = []
        
    def read(self , size):
        value = self._buffer[:size]
        self._buffer  = self._buffer[size:]
        return ''.join(value)
        
    def write(self ,data):
        self._buffer += list(data)
        if len(self._buffer) > self._maxSize:
            raise Exception("Internal buffering limit reached!")
        
    def close(self):
        self._buffer = None