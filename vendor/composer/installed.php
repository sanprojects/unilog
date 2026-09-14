<?php return array(
    'root' => array(
        'name' => 'sanprojects/unilog',
        'pretty_version' => 'dev-main',
        'version' => 'dev-main',
        'reference' => 'b9a3553a6bec41b3a0c2e8a8db02c5f3e90b4121',
        'type' => 'library',
        'install_path' => __DIR__ . '/../../',
        'aliases' => array(),
        'dev' => true,
    ),
    'versions' => array(
        'monolog/monolog' => array(
            'pretty_version' => '3.12.0',
            'version' => '3.12.0.0',
            'reference' => '72c534fc0ab181ef52d92a68382318631e301608',
            'type' => 'library',
            'install_path' => __DIR__ . '/../monolog/monolog',
            'aliases' => array(),
            'dev_requirement' => true,
        ),
        'psr/log' => array(
            'pretty_version' => '3.0.2',
            'version' => '3.0.2.0',
            'reference' => 'f16e1d5863e37f8d8c2a01719f5b34baa2b714d3',
            'type' => 'library',
            'install_path' => __DIR__ . '/../psr/log',
            'aliases' => array(),
            'dev_requirement' => true,
        ),
        'psr/log-implementation' => array(
            'dev_requirement' => true,
            'provided' => array(
                0 => '3.0.0',
            ),
        ),
        'sanprojects/unilog' => array(
            'pretty_version' => 'dev-main',
            'version' => 'dev-main',
            'reference' => 'b9a3553a6bec41b3a0c2e8a8db02c5f3e90b4121',
            'type' => 'library',
            'install_path' => __DIR__ . '/../../',
            'aliases' => array(),
            'dev_requirement' => false,
        ),
    ),
);
