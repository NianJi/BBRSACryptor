Pod::Spec.new do |s|
  s.name         = "BBRSACryptor"
  s.version      = "0.0.4"
  s.summary      = "RSA cryptor."
  s.description  = "使用OpenSSL的Api进行RSA的加密和解密，支持公钥加密，私钥解密；私钥加密，公钥解密."
  s.homepage     = "https://github.com/NianJi/BBRSACryptor"
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { "liukun" => "765409243@qq.com" }
  s.ios.deployment_target = '6.0'
  s.osx.deployment_target = '10.10'
  s.source       = { :git => "https://github.com/NianJi/BBRSACryptor.git", :tag => "0.0.4" }
  s.source_files  = 'BBRSACryptor', 'BBRSACryptor/**/*.{h,m}'
  s.frameworks = 'Foundation'
  s.dependency 'OpenSSL'
  s.requires_arc = true
end
