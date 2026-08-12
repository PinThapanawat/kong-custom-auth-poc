local typedefs = require "kong.db.schema.typedefs"

return {
  name = "custom-auth",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          {
            auth_service_url = {
              type = "string",
              required = true,
              match = "^https?://"
            }
          },
          {
            timeout_ms = {
              type = "number",
              default = 3000,
              between = { 100, 10000 }
            }
          },
          {
            enable_cache = {
              type = "boolean",
              default = true
            }
          },
          {
            cache_ttl_seconds = {
              type = "number",
              default = 60,
              between = { 1, 3600 }
            }
          }
        }
      }
    }
  }
}
