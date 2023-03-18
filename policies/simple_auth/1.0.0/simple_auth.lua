local errors = require('apicast.errors')
local resty_lrucache = require('resty.lrucache')

local _M = require('apicast.policy').new('File Authorize', '1.0.0')

local new = _M.new

function _M.new(config)
    local cache = _M.shared_cache() or error('missing cache store')

    if not cache then
        ngx.log(ngx.WARN, 'apicast cache error missing shared memory zone api_keys')
    end

    local self = new(config)

    self.auth_type = config.auth_type or 'none'
    -- self.auth_key = config.auth_key or 'user_key'
    self.keys_file = config.keys_file or '/opt/app/keys'
    self.keys = {}
    
    if self.auth_key ~= 'none' then       
      if config.keys ~= nil then 
        for _,v in ipairs(config.keys) do self.keys[v] = v end
      end
      
      local filename = self.keys_file
      
      -- load file with keys
      local f = io.open(filename, "r")
      if f then
        f:close()

        for line in io.lines(filename) do
          self.keys[line] = line
        end
        ngx.log(ngx.INFO,'loaded additional keys from file: [', filename, '].')
      else
        ngx.log(ngx.WARN,'missing keys file: [', filename, '].')
      end
    end
        
    self.cache = cache

    return self
end

function _M:rewrite(context)
    local auth_type = self.auth_type

    if self.auth_type == 'none' then
      context.extracted_credentials = {}
      ngx.log(ngx.INFO, 'Provided default creds for request')
    end

    context.skip_apicast_access = true
end

function _M:access(context)
    local ctx = ngx.ctx
    local p = context and context.proxy or ctx.proxy or self.proxy

    local final_usage = context.usage

    -- If routing policy changes the upstream and it only belongs to a specified
    -- owner, we need to filter out the usage for APIs that are not used at all.
    -- if context.route_upstream_usage_cleanup then
    --   context:route_upstream_usage_cleanup(final_usage, ctx.matched_rules)
    -- end
  
    return self:authorize(context, context.service, final_usage, context.credentials, context.ttl)
end

function _M:authorize(context, service, usage, credentials, ttl)
    -- if not usage or not credentials then return nil, 'missing usage or credentials' end
    if not usage then return nil, 'missing usage' end

    local formatted_usage = usage:format()

    local encoded_usage = usage:encoded_format()
    if encoded_usage == '' then
      return errors.no_match(service)
    end
    -- local encoded_credentials = encode_args(credentials)

    -- output_debug_headers(service, encoded_usage, encoded_credentials)

    -- -- NYI: return to lower frame
    local cached_key = ngx.var.cached_key .. ":" .. encoded_usage

    -- local encoded_extra_params = encode_args(self.extra_params_backend_authrep)
    -- if encoded_extra_params ~= '' then
    --   cached_key = cached_key .. ":" .. encoded_extra_params
    -- end

    local cache = self.cache
    local is_known = cache:get(cached_key)

    if is_known == 200 then
      ngx.log(ngx.DEBUG, 'apicast cache hit key: ', cached_key)
      ngx.var.cached_key = cached_key
    else
      ngx.log(ngx.INFO, 'apicast cache miss key: ', cached_key, ' value: ', is_known)

      -- set cached_key to nil to avoid doing the authrep in post_action
      ngx.var.cached_key = nil

      local authentication = self.auth_type

      ngx.log(ngx.NOTICE,'using authentication type: ', authentication)

      if authentication == 'none' then
        ngx.log(ngx.NOTICE,'all good!')
      else
        if not credentials then
          return nil, 'missing credentials'
        end
        -- local auth_key = self.auth_key
        local key = credentials['user_key'] or 'no key'
    
        ngx.log(ngx.NOTICE,'checking credentials: ', key)

        local keys = self.keys

        if not keys or next(keys) == nil then
          ngx.log(ngx.WARN,'no keys available. every request will be denied.')
          return errors.authorization_failed(service)
        end

        if not keys[key] then
          return errors.authorization_failed(service)
        end
      end
    end
end

function _M.shared_cache()
    return ngx.shared.api_keys or resty_lrucache.new(1)
end

return _M