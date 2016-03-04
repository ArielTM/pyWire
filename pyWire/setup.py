from distutils.core import setup
setup(name='pyWire',
      description = 'Python Interface to Wireshark.',
      author = 'SnifferMaster',
      version = '2.3',
      packages = ['pyWire'
      ,'pyWire.capture'
      ,'pyWire.capture.fileformats'
      ,'pyWire.packet'
      ,'pyWire.tshark'],
      )