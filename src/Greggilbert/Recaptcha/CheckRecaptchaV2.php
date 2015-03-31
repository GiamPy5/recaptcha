<?php

namespace Greggilbert\Recaptcha;

/**
 * Handle sending out and receiving a response to validate the captcha
 */
class CheckRecaptchaV2 implements RecaptchaInterface
{

	/**
	 * Call out to reCAPTCHA and process the response
	 * @param string $challenge
	 * @param string $response
	 * @return bool
	 */
	public function check($challenge, $response)
	{
		$parameters = http_build_query(array(
			'secret'        => app('config')->get('recaptcha::config.private_key'),
			'remoteip'		=> app('request')->getClientIp(),
			'response'      => $response,
		));
        
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $checkResponse = null;
        
        // prefer curl, but fall back to file_get_contents
        if('curl' === app('config')->get('recaptcha::config.driver') && function_exists('curl_version'))
        {
            $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_POST,           true);
            curl_setopt($curl, CURLOPT_POSTFIELDS,     $parameters);
            curl_setopt($curl, CURLOPT_HEADER,         false);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_TIMEOUT,        app('config')->get('recaptcha::config.options.timeout', 10));
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);

            $checkResponse = curl_exec($curl);
        }
        else
        {
            $opts = ['http' =>
                [
                    'method'  => 'POST',
                    'header'  => 'Content-type: application/x-www-form-urlencoded',
                    'content' => http_build_query($parameters),
                    'timeout' => app('config')->get('recaptcha::config.options.timeout', 10)
                ]
            ];

            $context = stream_context_create($opts);
            $checkResponse = file_get_contents($url, false, $context);
        }
        
        if(is_null($checkResponse) || empty($checkResponse))
        {
            return false;
        }

        $decodedResponse = json_decode($checkResponse, true);
		return $decodedResponse['success'];
	}

    public function getTemplate()
    {
        return 'captchav2';
    }
    
    public function getResponseKey()
    {
        return 'g-recaptcha-response';
    }
}