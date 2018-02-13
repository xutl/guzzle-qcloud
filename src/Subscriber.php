<?php
/**
 * @link http://www.tintsoft.com/
 * @copyright Copyright (c) 2012 TintSoft Technology Co. Ltd.
 * @license http://www.tintsoft.com/license/
 */

namespace xutl\guzzle\subscriber;

use Psr\Http\Message\RequestInterface;

class Subscriber
{
    /** @var array Configuration settings */
    private $config;

    const SIGNATURE_METHOD_HMAC_SHA1 = 'HmacSHA1';
    const SIGNATURE_METHOD_HMAC_SHA256 = 'HmacSHA256';

    /**
     * Subscriber constructor.
     * @param array $config
     */
    public function __construct($config)
    {
        $this->config = [
            'secretId' => '123456',
            'secretKey' => '654321',
            'SignatureMethod' => self::SIGNATURE_METHOD_HMAC_SHA256,
            'region' => '',
        ];
        foreach ($config as $key => $value) {
            $this->config[$key] = $value;
        }
    }

    /**
     * Called when the middleware is handled.
     *
     * @param callable $handler
     *
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function ($request, array $options) use ($handler) {
            $request = $this->onBefore($request);
            return $handler($request, $options);
        };
    }

    /**
     * 请求前调用
     * @param RequestInterface $request
     * @return RequestInterface
     */
    private function onBefore(RequestInterface $request)
    {
        $params = \GuzzleHttp\Psr7\parse_query($request->getBody()->getContents());
        if (!empty($this->config['region']) && !isset($params['Region'])) {
            $params['Region'] = $this->config['region'];
        }
        $params['SecretId'] = $this->config['secretId'];
        $params['Nonce'] = uniqid();
        $params['Timestamp'] = time();
        $params['RequestClient'] = 'guzzleHttp';
        $params['SignatureMethod'] = $this->config['SignatureMethod'];
        ksort($params);
        $url = str_replace(['http://', 'https://'], '', $request->getUri());
        $i = 0;
        foreach ($params as $key => $val) {
            if ($key == 'Signature' || ($request->getMethod() == 'POST' && substr($val, 0, 1) == '@')) {
                continue;
            }
            // 把 参数中的 _ 替换成 .
            if (strpos($key, '_')) {
                $key = str_replace('_', '.', $key);
            }
            $url .= ($i == 0) ? '?' : '&';
            $url .= $key . '=' . $val;
            ++$i;
        }
        $plainText = $request->getMethod() . $url;
        //签名
        if ($this->config['SignatureMethod'] == self::SIGNATURE_METHOD_HMAC_SHA256) {
            $params['Signature'] = base64_encode(hash_hmac('sha256', $plainText, $this->config['secretKey'], true));
        } elseif ($this->config['SignatureMethod'] == self::SIGNATURE_METHOD_HMAC_SHA1) {
            $params['Signature'] = base64_encode(hash_hmac('sha1', $plainText, $this->config['secretKey'], true));
        }
        $query = \GuzzleHttp\Psr7\build_query($params);
        $request->withBody($query);
        return $request;
    }
}