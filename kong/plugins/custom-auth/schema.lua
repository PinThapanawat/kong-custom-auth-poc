return {
  name = "custom-auth",
  fields = {
    { config = {
        type = "record",
        fields = {
          { pds_verify_url = { type = "string", required = true, match = "^https?://" } },
          { pds_encrypt_response_url = { type = "string", required = true, match = "^https?://" } },
          { account_service_url = { type = "string", required = true, match = "^https?://" } },
          { timeout_ms = { type = "integer", default = 5000, between = { 100, 30000 } } },
        },
      },
    },
  },
}
