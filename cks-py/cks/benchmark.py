def read_input(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
        lines = [l.strip() for l in lines]
        data = [float(l) for l in lines]
        return data

def read_twocolumn(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
        lines = [l.strip() for l in lines]
        data = []
        for l in lines:
            start, stop = l.split(" ")
            start = float(start)
            stop = float(stop)
            data.append(stop - start)
        return data
