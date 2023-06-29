import timeit
import math

class Test:

    def __init__(self) -> None:
        self.dispatcher = {
            0: self.a,
            1: self.b
        }

    def select(self, k):
        IEs = []
        IEs.append({'id': 1, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'gNB-ID': ('gNB-ID', (1, 32))}))})
        return self.dispatcher[k](IEs)

    # Function A
    def a(self, IEs):
        IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
        return IEs[0]['id'] * 2 * math.pi

    # Function B
    def b(self, IEs):
        IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
        return IEs[0]['id'] * 2 * math.pi
    
    def run(self):
        for i in range(100):
            self.select(i % 2)

a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())