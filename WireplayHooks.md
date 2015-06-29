# Wireplay Hooks #

Wireplay has a built in hook/plugin subsystem through which external plugins can register with the core. Wireplay has a Ruby Hook System built into it using which hooks can be written easily in Ruby.

The general idea about writing hooks in C can be best illustrated by walking through the Ruby Hook Plugin (src/whook\_rb.c):

```
/* define the hook object and assign appropriate call back functions */
static struct w_hook rb_hook = {
   .name    = "ruby",
   .init    = rb_w_hook_init,
   .start   = rb_w_event_start,
   .data    = rb_w_event_data,
   .stop    = rb_w_event_stop,
   .error   = rb_w_event_error,
   .deinit  = rb_w_hook_deinit
};
```

As you can see, Wireplay supports the following events:

  * init: When the hook is initialized
  * start: When new TCP connection is made with the target
  * data: When data is about to be sent to the peer
  * stop: When the connection is closed
  * error: When an error occurs
  * deinit: When wireplay is cleaning up

```
/* Finally, register the hook descriptor with the core */
w_register_hook(&rb_hook, &rb_hook_conf);
```

## Wireplay Hooks in Ruby ##

```
class MySampleHook
   def initialize
      puts ">> MySampleHook initialized"
   end

   def on_start(desc)
      puts ">> MySampleHook start (desc: #{desc.inspect})"
   end

   # 
   # If this method returns nil, then Wireplay assumes data
   # is not changed. If it returns a string, then Wireplay
   # sends the string instead of the original data
   #
   def on_data(desc, direction, data)
      puts ">> MySampleHook data (desc: #{desc.inspect})"
      puts ">> MySampleHook data (direction: #{direction})"
      puts ">> MySampleHook data (data size: #{data.size})"
   end

   def on_stop(desc)
      puts ">> MySampleHook stop (desc: #{desc.inspect})"
   end
end

Wireplay::Hooks.register(MySampleHook.new)
```

As you can see, _desc_ is sent to every event handler method in the above example. _desc_ is actually a Ruby OpenStruct object, created in C-land and is similar to the example below:

```
irb(main):002:0> desc = OpenStruct.new
=> #<OpenStruct>
irb(main):003:0> desc.host = "192.168.0.2"
=> "192.168.0.2"
irb(main):004:0> desc.port = 80
=> 80
irb(main):005:0> desc.run_count = 10
=> 10
irb(main):006:0> desc.role = 1
=> 1
irb(main):007:0> desc.inspect
=> "#<OpenStruct host=\"192.168.0.2\", port=80, run_count=10, role=1>"
irb(main):008:0>
```

The desc object represents the connection descriptor.