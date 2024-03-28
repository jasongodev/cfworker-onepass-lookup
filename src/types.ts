import { Context } from 'hono'
import type { Bindings, Variables, Env } from 'hono/types'

interface CustomBindings extends Bindings {
  ENVIRONMENT?: string
  TURNSTILE_ALLOWED_HOSTNAMES?: string[]

  // Set the following using the wrangler cli
  // NEVER PLACE YOUR KEYS IN wrangler.toml
  // NOT EVEN YOUR DEV OR TEST KEYS!

  // wrangler secret put TURNSTILE_SECRET
  TURNSTILE_SECRET?: string

  // wrangler secret put ONEPASS_ID
  ONEPASS_ID?: string

  // wrangler secret put ONEPASS_SECRET
  ONEPASS_SECRET?: string
}

interface CustomVariables extends Variables {
  allowedHostnames: string[]
  origin: string
}

export interface CustomEnv extends Env {
  Bindings?: CustomBindings
  Variables: CustomVariables
}

export interface CustomContext extends Context<CustomEnv> {}

export interface TurnstileChallenge {
  success: boolean
  hostname?: string
  cdata?: string
}

export interface OnepassToken {
  access_token?: string
}
