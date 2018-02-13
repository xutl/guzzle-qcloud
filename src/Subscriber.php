<?php
/**
 * @link http://www.tintsoft.com/
 * @copyright Copyright (c) 2012 TintSoft Technology Co. Ltd.
 * @license http://www.tintsoft.com/license/
 */

namespace xutl\guzzle\qcloud;

use function GuzzleHttp\default_user_agent;
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
            'signatureMethod' => self::SIGNATURE_METHOD_HMAC_SHA256,
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
        $request->withAddedHeader('User-Agent', default_user_agent());
        if ($request->getMethod() == 'GET') {
            $params = \GuzzleHttp\Psr7\parse_query($request->getUri()->getQuery());
        } else if ($request->getMethod() == 'POST') {
            $params = \GuzzleHttp\Psr7\parse_query($request->getBody()->getContents());
        } else {
            return $request;
        }

        $params['SecretId'] = $this->config['secretId'];
        $params['Nonce'] = uniqid();
        $params['Timestamp'] = time();
        $params['RequestClient'] = 'GuzzleHttp';
        $params['SignatureMethod'] = $this->config['signatureMethod'];
        if (!empty($this->config['region']) && !isset($params['Region'])) {
            $params['Region'] = $this->config['region'];
        }
        ksort($params);
        $url = $request->getUri()->getHost() . $request->getUri()->getPath();
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
        if ($this->config['signatureMethod'] == self::SIGNATURE_METHOD_HMAC_SHA256) {
            $params['Signature'] = base64_encode(hash_hmac('sha256', $plainText, $this->config['secretKey'], true));
        } elseif ($this->config['signatureMethod'] == self::SIGNATURE_METHOD_HMAC_SHA1) {
            $params['Signature'] = base64_encode(hash_hmac('sha1', $plainText, $this->config['secretKey'], true));
        }
        $query = \GuzzleHttp\Psr7\build_query($params);
        if ($request->getMethod() == 'GET') {
            $request = $request->withUri($request->getUri()->withQuery($query));
        } else if ($request->getMethod() == 'POST') {
            $body = \GuzzleHttp\Psr7\stream_for($query);
            $request = $request->withBody($body);
        } else {
            return $request;
        }
        return $request;
    }
}