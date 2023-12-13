import time
import sys


def loading_bar(iterations, delay=0.1):
    for _ in range(iterations):
        sys.stdout.write('\rSending to client' + '.' * _ +
                         ' ' * (iterations - _ - 1))
        sys.stdout.flush()
        time.sleep(0.1)


# Example usage
loading_bar(10)
print("\nLoading complete!")
