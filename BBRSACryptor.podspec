#
#  Be sure to run `pod spec lint BBRSACryptor.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|

  s.name         = "BBRSACryptor"
  s.version      = "1.0"
  s.summary      = "使用OpenSSL的Api进行RSA的加密和解密，支持公钥加密，私钥解密；私钥加密，公钥解密"
  s.homepage     = "http://cnbluebox.com/BBRSACryptor"
  s.license      = 'MIT'
  s.author             = { "liukun" => "765409243@qq.com" }
  s.platform     = :ios, '5.0'
  s.source       = { :git => "git@www.cnbluebox.com:BBRSACryptor.git", :tag => "1.0" }
#  s.source       = { :git => "/Users/liukun/Code/bluebox/BBRSACryptor" }
  s.source_files  = 'BBRSACryptor', 'BBRSACryptor/**/*.{h,m}'
  s.subspec 'GTMBase64' do |ss|
    ss.source_files = 'GTMBase64/*.{h,m}'
  end 
  s.subspec 'OpenSSL' do |ss|
    ss.subspec 'include' do |sss|
        sss.subspec 'openssl' do |ssss|
          ssss.source_files = 'OpenSSL/include/**/*.h'
          ssss.header_mappings_dir = 'OpenSSL/include'
        end
    end
    ss.vendored_libraries = 'OpenSSL/lib/libcrypto.a', 'OpenSSL/lib/libssl.a'
  end 
  s.requires_arc = true
end
