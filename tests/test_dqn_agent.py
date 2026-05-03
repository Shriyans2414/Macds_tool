import os
import numpy as np
import torch
from control_plane.macds.agents.multi_agent import DQNAgent, STATE_DIM, N_ACTIONS

def test_encode_state():
    agent = DQNAgent("test")
    state = {"packet_rate": 1500, "cpu_usage": 50, "bandwidth_usage": 50, "attack_type": "syn_flood"}
    encoded = agent._encode_state(state)
    assert encoded.shape == (STATE_DIM,)
    assert 0.0 <= encoded[0] <= 1.0 # norm
    assert np.sum(encoded[8:]) == 1.0

def test_select_action():
    agent = DQNAgent("test", epsilon=0.0) # greedy
    state = {"packet_rate": 500, "cpu_usage": 50, "bandwidth_usage": 50, "attack_type": "syn_flood"}
    act = agent.select_action(state)
    assert act in agent.actions

def test_convergence():
    torch.manual_seed(0)
    import random; random.seed(0)
    import numpy as np; np.random.seed(0)
    
    agent = DQNAgent("test", alpha=0.01, epsilon=0.1, batch_size=16)
    agent.device = torch.device('cpu')
    state = {"packet_rate": 2000, "cpu_usage": 100, "bandwidth_usage": 100, "attack_type": "syn_flood"}
    for _ in range(250):
        agent.update(state, "block_ip", 10.0, state)
        agent.update(state, "do_nothing", -10.0, state)
    
    agent.epsilon = 0.0
    action = agent.select_action(state)
    assert action == "block_ip"

def test_save_load():
    agent = DQNAgent("test")
    agent._steps = 123
    agent.epsilon = 0.123
    
    path = "/tmp/qtables_test/test.pt"
    agent.save(path)
    
    new_agent = DQNAgent("test2")
    new_agent.load(path)
    assert new_agent._steps == 123
    assert new_agent.epsilon == 0.123
    
    if os.path.exists(path):
        os.remove(path)
