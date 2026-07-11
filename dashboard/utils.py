import heapq
import psutil

def dijkstra(nodes, links, start_id):
    graph = {node.id: [] for node in nodes}
    for link in links:
        graph[link.source_id].append((link.destination_id, link.weight))

    distances = {node_id: float('inf') for node_id in graph}
    distances[start_id] = 0
    pq = [(0, start_id)]

    while pq:
        current_dist, current_node = heapq.heappop(pq)
        if current_dist > distances[current_node]:
            continue
        for neighbor, weight in graph[current_node]:
            dist = current_dist + weight
            if dist < distances[neighbor]:
                distances[neighbor] = dist
                heapq.heappush(pq, (dist, neighbor))

    return distances

def get_if_list():
    try:
        return list(psutil.net_if_addrs().keys())
    except Exception:
        return []


def list_interfaces():
    return get_if_list()
