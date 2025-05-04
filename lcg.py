import configparser

config = configparser.ConfigParser()
config.read('config.txt')

LCG_A = int(config['DEFAULT']['LCG_A'])
LCG_C = int(config['DEFAULT']['LCG_C'])
LCG_M = int(config['DEFAULT']['LCG_M'])

class LCG:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (LCG_A * self.state + LCG_C) % LCG_M
        return self.state & 0xFF

    def generate_keystream(self, length):
        return bytes([self.next() for _ in range(length)])