import os

os.environ["MACDS_API_KEY"] = "test-key"
os.environ["QTABLE_DIR"] = "/tmp/qtables_test"
os.environ["SDN_MODE"] = "false"
os.environ["REDIS_URL"] = "redis://invalid_host:6379/1"
