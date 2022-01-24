#!/usr/bin/env ruby
require 'base64'
require 'json'
require 'openssl'

def to_jwk(kid, key, private_key: false)
  key = key.dup

  crv = case key.group.curve_name
        when 'prime256v1'
          'P-256'
        when 'secp384r1'
          'P-384'
        when 'secp521r1'
          'P-521'
        else
          raise "unknown curve"
        end

  # https://github.com/unixcharles/acme-client/blob/master/lib/acme/client/jwk/ecdsa.rb
  # https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
  hex = key.public_key.to_bn.to_s(16)
  data_len = hex.length - 2
  hex_x = hex[2, data_len / 2]
  hex_y = hex[2 + data_len / 2, data_len / 2]

  jwk = {
    use: "sig",
    kty: 'EC',
    crv: crv,
    kid: kid,
    x: Base64.urlsafe_encode64(OpenSSL::BN.new([hex_x].pack('H*'), 2).to_s(2)).gsub(/\n|=/, ''),
    y: Base64.urlsafe_encode64(OpenSSL::BN.new([hex_y].pack('H*'), 2).to_s(2)).gsub(/\n|=/, ''),
  }

  if private_key
    jwk[:d] = Base64.urlsafe_encode64(key.private_key.to_s(2)).gsub(/\n|=/, '')
  end

  jwk
end

private_key = OpenSSL::PKey::EC.new("prime256v1").tap(&:generate_key!)
service_key = OpenSSL::PKey::EC.new("prime256v1").tap(&:generate_key!)

File.open('./ecamo.pem', 'w', 0600) { |io| io.puts private_key.to_pem }
File.open('./service.pem', 'w', 0600) { |io| io.puts service_key.to_pem }



File.open('./env.sh', 'w', 0600) do |io|
  io.puts "export ECAMO_BIND=127.0.0.1:3000"
  io.puts "export ECAMO_CANONICAL_HOST=ecamo.lo.nkmiusercontent.com:3000"
  io.puts "export ECAMO_PRIVATE_SOURCE_ALLOWED_REGEXP=."
  io.puts "export ECAMO_INSECURE=true"

  public_keys = {
    "http://service.lo.nkmiusercontent.com:3001 svc" => to_jwk('svc', service_key),
  }
  io.puts "export ECAMO_SERVICE_PUBLIC_KEYS='#{public_keys.to_json}'"

  private_keys = {
    "prv" => to_jwk('prv', private_key, private_key: true),
  }
  io.puts "export ECAMO_PRIVATE_KEYS='#{private_keys.to_json}'"
  io.puts "export ECAMO_SIGNING_KID=prv"
end
File.write './fastly_dictionary_public_keys.json', "#{{prv: to_jwk("prv", private_key).to_json}.to_json}\n"
