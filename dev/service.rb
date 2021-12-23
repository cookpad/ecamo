require 'jwt'
require 'openssl'
require 'rack/reverse_proxy'
require 'sinatra'
require 'sinatra/cookies'

CONTENT_URL = 'https://avatars.githubusercontent.com/u/119195?s=200&v=4'

ECAMO_URL = 'http://ecamo.lo.nkmiusercontent.com:3000'
SERVICE_ORIGIN = 'http://service.lo.nkmiusercontent.com:3001'

KID = 'svc'
PKEY = OpenSSL::PKey::EC.new(File.read('./service.pem'), '')

def make_url_token(url)
  payload = {iss: SERVICE_ORIGIN, 'ecamo:url' => url, 'ecamo:send-token' => false}
  header = {kid: KID}
  JWT.encode(payload, PKEY, 'ES256', header)
end

def make_auth_cookie()
  payload = {iss: SERVICE_ORIGIN, aud: ECAMO_URL, exp: (Time.now + 300).to_i, sub: 'subj'}
  header = {kid: KID}
  JWT.encode(payload, PKEY, 'ES256', header)
end

get '/' do
  token = make_url_token(CONTENT_URL)
  <<~EOF
  <p><img src="/.ecamo/v1/r/#{token}"></p>

  <p style='font-size: 0.5rem'><b>Cookie:</b> #{request.cookies['ecamo_token'].inspect}</p>

  <form action="/login" method="POST">
    <button>Set Auth Cookie</button>
  </form>

  <form action="/logout" method="POST">
    <button>Give up Auth Cookie</button>
  </form>

  EOF
end

post '/login' do
  cookies.set('ecamo_token', value: make_auth_cookie(), expires: Time.now+290)
  cookies['ecamo_token'] = make_auth_cookie()
  redirect '/'
end

post '/logout' do
  cookies.delete('ecamo_token')
  redirect '/'
end

use Rack::ReverseProxy do
  reverse_proxy_options preserve_host: false
  reverse_proxy /^\/\.ecamo(\/.*$)/, "#{ECAMO_URL}/.ecamo$1"
end
