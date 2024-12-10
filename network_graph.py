import networkx as nx

class NetworkGraph:
    def __init__(self):
        self.graph = nx.Graph()

    def add_connection(self, node1, node2, latency):
        self.graph.add_edge(node1, node2, weight=latency)

    def remove_connection(self, node1, node2):
        if self.graph.has_edge(node1, node2):
            self.graph.remove_edge(node1, node2)

    def get_connections(self):
        return [
            (node1, node2, data['weight'])
            for node1, node2, data in self.graph.edges(data=True)
        ]

    def __str__(self):
        connections = self.get_connections()
        result = "Network Connections:\n"
        for node1, node2, weight in connections:
            result += f"{node1} --({weight}ms)-- {node2}\n"
        return result

