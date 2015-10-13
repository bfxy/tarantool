env = require('test_run')
test_run = env.new('localhost', 8080)
box.schema.user.grant('guest', 'read,write,execute', 'universe')

net_box = require('net.box')
errinj = box.error.injection

box.schema.user.grant('guest', 'replication')
test_run:cmd("create server replica with rpl_master=default, script='replication/replica.lua'")
test_run:cmd("start server replica")
test_run:cmd("switch replica")

test_run:cmd("switch default")
s = box.schema.space.create('test');
index = s:create_index('primary', {type = 'hash'})

test_run:cmd("switch replica")
fiber = require('fiber')
while box.space.test == nil do fiber.sleep(0.01) end
test_run:cmd("switch default")
test_run:cmd("stop server replica")

-- insert values on the master while replica os stopped and can't fetch them
for i=1,100 do s:insert{i, 'this is test message12345'} end

-- sleep after every tuple
errinj.set("ERRINJ_RELAY", true)

test_run:cmd("start server replica")
test_run:cmd("switch replica")

-- Check that replica doesn't enter read-write mode
-- before catching up with the master: to check that we inject
-- sleep into the master relay_send function and attempt a data
-- modifying statement in replica while it's still fetching
-- data from the master.
-- In next 2 cases we try to delete tuple
-- during fetching process(local delete, remote delete)
-- case #1: delete tuple in replica
box.space.test:len()
d = box.space.test:delete{1}
box.space.test:get(1) ~= nil

-- case #2: delete tuple by net.box
test_run:cmd("switch default")
test_run:cmd("set variable r_uri to 'replica.listen'")
c = net_box:new(r_uri)
d = c.space.test:delete{1}
c.space.test:get(1) ~= nil

-- check sync
errinj.set("ERRINJ_RELAY", false)

-- cleanup
test_run:cmd("stop server replica")
test_run:cmd("cleanup server replica")
box.space.test:drop()
box.schema.user.revoke('guest', 'replication')

