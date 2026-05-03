from control_plane.macds.agents.multi_agent import MultiAgentSystem

def test_coordinate_block_ip():
    mas = MultiAgentSystem()
    actions = {"ids_agent": "raise_alert", "traffic_agent": "do_nothing", "response_agent": "block_ip"}
    assert mas.coordinate(actions, state=None) == "block_ip"

def test_coordinate_unblock_ip():
    mas = MultiAgentSystem()
    actions_1 = {"ids_agent": "unblock_ip", "traffic_agent": "do_nothing", "response_agent": "raise_alert"}
    assert mas.coordinate(actions_1, state=None) == "raise_alert"
    
    actions_2 = {"ids_agent": "unblock_ip", "traffic_agent": "unblock_ip", "response_agent": "raise_alert"}
    assert mas.coordinate(actions_2, state=None) == "unblock_ip"

def test_learn_calls_agents():
    mas = MultiAgentSystem()
    state = {"packet_rate": 50, "cpu_usage": 20, "bandwidth_usage": 20, "attack_type": "none"}
    
    mas.learn(state, "do_nothing", 1.0, state)
    
    assert len(mas.agents["ids_agent"].replay.buf) > 0
    assert len(mas.agents["traffic_agent"].replay.buf) > 0
    assert len(mas.agents["response_agent"].replay.buf) > 0
