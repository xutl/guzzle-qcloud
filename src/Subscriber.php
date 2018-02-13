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
            $request->withUri($request->getUri()->withQuery($this->makeParams($request, $params)));
        } else if ($request->getMethod() == 'POST') {
            $params = \GuzzleHttp\Psr7\parse_query($request->getBody()->getContents());
            $request->withBody(\GuzzleHttp\Psr7\stream_for($this->makeParams($request, $params)));
        }
        return $request;
    }

    /**
     * 组装参数
     * @param RequestInterface $request
     * @param array $params
     * @return string
     */
    public function makeParams(RequestInterface $request, array $params)
    {
        $params['SecretId'] = $this->config['secretId'];
        $params['Nonce'] = uniqid();
        $params['Timestamp'] = time();
        $params['RequestClient'] = default_user_agent();
        $params['SignatureMethod'] = $this->config['signatureMethod'];
        if (!empty($this->config['region']) && !isset($params['Region'])) {
            $params['Region'] = $this->config['region'];
        }
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
        if ($this->config['signatureMethod'] == self::SIGNATURE_METHOD_HMAC_SHA256) {
            $params['Signature'] = base64_encode(hash_hmac('sha256', $plainText, $this->config['secretKey'], true));
        } elseif ($this->config['signatureMethod'] == self::SIGNATURE_METHOD_HMAC_SHA1) {
            $params['Signature'] = base64_encode(hash_hmac('sha1', $plainText, $this->config['secretKey'], true));
        }
        return \GuzzleHttp\Psr7\build_query($params);
    }
}