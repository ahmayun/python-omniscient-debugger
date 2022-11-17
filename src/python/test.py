from pystrace import Tracer




def on_event(event):
    print("event")
    breakpoint()

my_tracer = Tracer(["id"], on_event)
my_tracer.run()