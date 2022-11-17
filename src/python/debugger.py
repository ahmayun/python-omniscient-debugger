#!/bin/python3
import sys
import argparse

def setup_argparser():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", help="specify target program")

    return parser.parse_args()


class Debugger:
    def __init__(self, filename):
        print("Debugger initialized for {filename}")


def main(args):
    target_program = args.target
    print(target_program)

    debugger = Debugger(target_program)


if __name__ == "__main__":
    main(setup_argparser())