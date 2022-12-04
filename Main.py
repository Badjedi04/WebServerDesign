from src.Server import Server


if __name__ == "__main__":
    s = Server("0.0.0.0", 80)
    s.activate_server()
