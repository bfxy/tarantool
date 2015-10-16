
-- gh-283: hang after three creates and drops
s = box.schema.space.create('space0', {engine='sophia'})
i = s:create_index('space0', {type = 'tree', parts = {1, 'STR'}})
s:insert{'a', 'b', 'c'}
s:drop()

s = box.schema.space.create('space0', {engine='sophia'})
i = s:create_index('space0', {type = 'tree', parts = {1, 'STR'}})
s:insert{'a', 'b', 'c'}
t = s.index[0]:select({}, {iterator = box.index.ALL})
t
s:drop()

s = box.schema.space.create('space0', {engine='sophia'})
i = s:create_index('space0', {type = 'tree', parts = {1, 'STR'}})
s:insert{'a', 'b', 'c'}
t = s.index[0]:select({}, {iterator = box.index.ALL})
t
s:drop()


-- gh-280: crash if insert without index
s = box.schema.space.create('test', {engine='sophia'})
s:insert{'a'}
s:drop()


-- gh-436: No error when creating temporary sophia space
s = box.schema.space.create('tester',{engine='sophia', temporary=true})


-- gh-432: ignored limit
s = box.schema.space.create('tester',{engine='sophia'})
i = s:create_index('sophia_index', {})
for v=1, 100 do s:insert({v}) end
t = s:select({''},{iterator='GT', limit =1})
t
t = s:select({},{iterator='GT', limit =1})
t
s:drop()

s = box.schema.space.create('tester', {engine='sophia'})
i = s:create_index('sophia_index', {type = 'tree', parts = {1, 'STR'}})
for v=1, 100 do s:insert({tostring(v)}) end
t = s:select({''},{iterator='GT', limit =1})
t
t = s:select({},{iterator='GT', limit =1})
t
s:drop()


-- gh-681: support or produce error on space::alter
s = box.schema.space.create('M', {engine='sophia'})
i = s:create_index('primary',{})
s:insert{5}
s.index.primary:alter({parts={1,'NUM'}})
s:drop()


-- gh-1008: assertion if insert of wrong type
s = box.schema.space.create('t', {engine='sophia'})
i = s:create_index('primary',{parts={1, 'STR'}})
box.space.t:insert{1,'A'}
s:drop()


-- gh-1009: search for empty string fails
s = box.schema.space.create('t', {engine='sophia'})
i = s:create_index('primary',{parts={1, 'STR'}})
s:insert{''}
#i:select{''}
i:get{''}
s:drop()


-- gh-1015: assertion if nine indexed fields
s = box.schema.create_space('t',{engine='sophia'})
i = s:create_index('primary',{parts={1,'str',2,'str',3,'str',4,'str',5,'str',6,'str',7,'str',8,'str',9,'str'}})
s:insert{'1','2','3','4','5','6','7','8','9'}
s:drop()


-- gh-1016: behaviour of multi-part indexes
s = box.schema.create_space('t',{engine='sophia'})
i = s:create_index('primary',{parts={1,'str',2,'str',3,'str'}})
s:insert{'1','2','3'}
s:insert{'1','2','0'}
i:select({'1','2',nil},{iterator='GT'})
s:drop()
