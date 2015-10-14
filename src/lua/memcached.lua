-- memcached.lua

local ffi    = require('ffi')
local mcfg   = require('memcached_config')
package.loaded['memcached_config'] = nil
local socket = require('socket')
local errno  = require('errno')
local uri    = require('uri')
local log    = require('log')

local fmt = string.format

ffi.cdef[[
struct memcached_stat {
    /* connection informations */
    unsigned int  curr_items;
    unsigned int  total_items;
    unsigned int  curr_conns;
    unsigned int  total_conns;
    uint64_t      bytes_read;
    uint64_t      bytes_written;
    /* get statistics */
    uint64_t      cmd_get;
    uint64_t      get_hits;
    uint64_t      get_misses;
    /* delete stats */
    uint64_t      cmd_delete;
    uint64_t      delete_hits;
    uint64_t      delete_misses;
    /* set statistics */
    uint64_t      cmd_set;
    uint64_t      cas_hits;
    uint64_t      cas_badval;
    uint64_t      cas_misses;
    /* incr/decr stats */
    uint64_t      cmd_incr;
    uint64_t      incr_hits;
    uint64_t      incr_misses;
    uint64_t      cmd_decr;
    uint64_t      decr_hits;
    uint64_t      decr_misses;
    /* touch/flush stats */
    uint64_t      cmd_touch;
    uint64_t      touch_hits;
    uint64_t      touch_misses;
    uint64_t      cmd_flush;
    /* expiration stats */
    uint64_t      evictions;
    uint64_t      reclaimed;
    /* authentication stats */
    uint64_t      auth_cmds;
    uint64_t      auth_errors;
};

void
memcached_set_opt (struct memcached_service *srv, int opt, ...);

enum memcached_options {
    MEMCACHED_OPT_READAHEAD = 0,
    MEMCACHED_OPT_EXPIRE_ENABLED,
    MEMCACHED_OPT_EXPIRE_COUNT,
    MEMCACHED_OPT_EXPIRE_TIME,
    MEMCACHED_OPT_FLUSH_ENABLED,
    MEMCACHED_OPT_VERBOSITY,
};

struct memcached_stat *memcached_get_stat (struct memcached_service *);

struct memcached_service *memcached_create(const char *, uint32_t);
void memcached_start (struct memcached_service *);
void memcached_stop  (struct memcached_service *);
void memcached_free  (struct memcached_service *);

void
memcached_handler(struct memcached_service *p, int fd);
]]

local memcached_services = {}
local RUNNING = 'r'
local STOPPED = 's'
local ERRORED = 'e'

local stat_table = {
    'total_items', 'curr_items', 'started',
    'curr_conns', 'total_conns',
    'bytes_read', 'bytes_written',
    'cmd_get', 'get_hits', 'get_misses',
    'cmd_delete', 'delete_hits', 'delete_misses',
    'cmd_set', 'cas_hits', 'cas_badval', 'cas_misses',
    'cmd_incr', 'incr_hits', 'incr_misses',
    'cmd_decr', 'decr_hits', 'decr_misses',
    'cmd_touch', 'touch_hits', 'touch_misses',
    'cmd_flush',
    'evictions', 'reclaimed',
    'auth_cmds', 'auth_errors'
}

local conf_table = {
    verbosity            = ffi.C.MEMCACHED_OPT_VERBOSITY,
    readahead            = ffi.C.MEMCACHED_OPT_READAHEAD,
    expire_enabled       = ffi.C.MEMCACHED_OPT_EXPIRE_ENABLED,
    expire_items_per_item= ffi.C.MEMCACHED_OPT_EXPIRE_COUNT,
    expire_full_scan_time= ffi.C.MEMCACHED_OPT_EXPIRE_TIME
}

local memcached_mt = {
    cfg = function (self, opts)
        if type(opts) ~= 'table' then
            error('arguments must be in dictionary')
        end
        local stat, err = mcfg.check(opts or {})
        if stat == false then
            error(err)
        end
        for k, v in pairs(opts) do
            if conf_table[k] ~= nil then
                ffi.C.memcached_set_opt(self.service, conf_table[k], v)
            end
        end
        return self
    end,
    start = function (self)
        local function memcached_handler(socket, addr)
            log.debug('client %s:%s connected', addr.host, addr.port)
            ffi.C.memcached_handler(self.service, socket:fd())
        end

        if self.status == RUNNING then
            error(fmt("memcached '%s' is already started", self.name))
        end
        ffi.C.memcached_start(self.service)
        local parsed = uri.parse(self.uri)
        self.listener = socket.tcp_server(
            parsed.host,
            parsed.service, {
                handler = memcached_handler
        })
        if self.listener == nil then
            self.status = ERRORED
            error(fmt('can\'t bind (%d) %s', errno(), errno.strerror()))
        end
        self.status = RUNNING
        return self
    end,
    stop = function (self)
        if self.status == STOPPED then
            error(fmt("memcached '%s' is already stopped", self.name))
        end
        if (self.listener ~= nil) then
            self.listener:close()
        end
        local rc = ffi.C.memcached_stop(self.service)
        self.status = STOPPED
    end,
    info = function (self)
        stats = ffi.C.memcached_get_stat(self.service)
        retval = {}
        for k, v in pairs(stat_table) do
            retval[v] = stats[0][v]
        end
        return retval
    end
}

local function memcached_init(name, uri, opts)
    opts = opts or {}
    local conf = mcfg.initial(opts)
    local instance = {}
    instance.opts = conf
    instance.name = name
    instance.uri  = uri
    local sname = '__mc_' .. instance.name
    if box.space[sname] ~= nil then
        error(fmt("Space with name '%s' is already created", sname))
    end
    instance.space = box.schema.create_space(sname)
    instance.space:create_index('primary', {
        parts = {1, 'str'},
        type = 'hash'
    })
    local service = ffi.C.memcached_create(instance.name, instance.space.id)
    if service == nil then
        error("can't allocate memory")
    end
    instance.service = ffi.gc(service, ffi.C.memcached_free)
    memcached_services[instance.name] = setmetatable(instance,
        { __index = memcached_mt }
    )
    return instance:cfg(opts):start()
end

return {
    create = memcached_init;
    get    = function (name) return memcached_services[name] end;
    debug  = memcached_services;
}
