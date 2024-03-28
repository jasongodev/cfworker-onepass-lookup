import { Hono } from 'hono'
import {
  CustomEnv,
  CustomContext,
  TurnstileChallenge,
  OnepassToken
} from './types'

const app = new Hono<CustomEnv>()

app.use('*', async (c: CustomContext, next) => {
  const allowedHostnames = c.env?.TURNSTILE_ALLOWED_HOSTNAMES ?? []
  const origin = new URL(c.req.header('origin') ?? '').hostname

  c.set('allowedHostnames', allowedHostnames)
  c.set('origin', origin)

  if (allowedHostnames.includes(origin)) {
    c.header('Access-Control-Allow-Origin', c.req.header('origin'))
  }
  c.header('Access-Control-Allow-Methods', 'POST')

  await next()
})

app.options('/', (c) => c.text('', 204))

app.post('/', async (c: CustomContext) => {
  const allowedHostnames = c.get('allowedHostnames')
  const origin = c.get('origin')

  if (
    !allowedHostnames.includes(origin) ||
    c.env?.TURNSTILE_SECRET === undefined ||
    c.env?.ONEPASS_ID === undefined ||
    c.env?.ONEPASS_SECRET === undefined
  ) {
    return c.json({ success: false, error: 'Misconfigured keys or hostname.' })
  }

  const token = await c.req.text()
  const remoteip = c.req.header('CF-Connecting-IP')

  const formData = new FormData()
  formData.append('secret', c.env?.TURNSTILE_SECRET)
  formData.append('response', token)

  if (remoteip !== undefined) formData.append('remoteip', remoteip)

  const challenge: TurnstileChallenge = await (
    await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData
    })
  )
    .json()
    .catch((e) => {
      return {}
    })

  if (
    // Challenge failed
    !challenge.success ||
    // or cdata is missing (no memberId)
    challenge.cdata === undefined ||
    // Or hostname and origin does not match
    (challenge.hostname !== undefined &&
      !allowedHostnames.includes(challenge.hostname))
  ) {
    return c.json({ success: false, error: 'Security challenge failed.' })
  }

  const onepassEndpoint =
    c.env?.ENVIRONMENT === 'production'
      ? 'https://api.uhg.com'
      : 'https://api-stg.uhg.com'

  let onepassToken: OnepassToken
  const onepassTokenText = await (
    await fetch(onepassEndpoint + '/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: c.env.ONEPASS_ID,
        client_secret: c.env.ONEPASS_SECRET,
        grant_type: 'client_credentials',
        scope: 'https://api.uhg.com/.default'
      }).toString()
    })
  ).text()

  try {
    onepassToken = JSON.parse(onepassTokenText)
  } catch (e) {
    return c.json({
      success: false,
      error: 'Onepass endpoint returned a non-JSON result: ' + onepassTokenText
    })
  }

  if (onepassToken?.access_token === undefined) {
    return c.json({
      success: false,
      error: 'Unauthorized to access Onepass.'
    })
  }

  const onepassMember = await (
    await fetch(
      onepassEndpoint +
        '/api/cloud/api-management/pass-edge/1.0.0/rest/pass-edge/v2/members/code/' +
        challenge.cdata,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-Upstream-Env': 'integration',
          Authorization: 'Bearer ' + onepassToken.access_token
        }
      }
    )
  )
    .json()
    .catch((e) => {
      return {}
    })

  return c.json({ success: true, data: onepassMember })
})

export default app
