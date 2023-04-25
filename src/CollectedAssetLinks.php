<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use Base64Url\Base64Url;
use InvalidArgumentException;

class CollectedAssetLinks
{

    /**
     * @var string
     */
    private $rawData;

    /**
     * @var mixed[]
     */
    private $data;

    /**
     * @var CollectedAssetLink[]
     */
    private $assetLinks;

    /**
     * @param mixed[] $data
     */
    public function __construct(string $rawData, array $data)
    {
        $this->assetLinks = [];
        foreach ($data as $assetLink) {
            $this->assetLinks[] = new CollectedAssetLink($assetLink);
        }
        $this->rawData = $rawData;
        $this->data = $data;
    }

    public static function createFromJson(string $data): self
    {
        $json = json_decode($data, true);
        Assertion::isArray($json, 'Invalid collected client data');

        return new self($data, $json);
    }

    /**
     * @return CollectedAssetLink[]
     */
    public function getAssetLinks(): array
    {
        return $this->assetLinks;
    }

    /**
     * @return string[]
     */
    public function all(): array
    {
        return array_keys($this->data);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * @return mixed
     */
    public function get(string $key)
    {
        if (!$this->has($key)) {
            throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
        }

        return $this->data[$key];
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }
}

class CollectedAssetLink
{
    /** @var string[] */
    private $relation;

    /** @var string */
    private $targetNamespace;

    /** @var ?string */
    private $targetPackageName;

    /** @var string[]|null */
    private $targetSha256CertFingerPrints;

    /** @var ?string */
    private $targetSite;

    /**
     * @param mixed[] $data
     */
    public function __construct(
        array $data
    ) {
        $this->relation = $this->findData($data, 'relation', true);
        $target = $this->findData($data, 'target', true);
        $this->targetNamespace = $this->findData($target, 'namespace', true);
        $this->targetPackageName = $this->findData($target, 'package_name', false);
        $this->targetSha256CertFingerPrints = $this->findData($target, 'sha256_cert_fingerprints', false);
        $this->targetSite = $this->findData($target, 'site', false);
    }

    public function getRelation(): array
    {
        return $this->relation;
    }

    public function getTargetNamespace(): string
    {
        return $this->targetNamespace;
    }

    public function getTargetPackageName(): ?string
    {
        return $this->targetPackageName;
    }

    public function getTargetSha256CertFingerPrints(): ?array
    {
        return $this->targetSha256CertFingerPrints;
    }

    public function getTargetSite(): ?string
    {
        return $this->targetSite;
    }

    /**
     * @param mixed[] $json
     *
     * @return mixed|null
     */
    private function findData(array $json, string $key, bool $isRequired = true, bool $isB64 = false)
    {
        if (!array_key_exists($key, $json)) {
            if ($isRequired) {
                throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
            }

            return;
        }

        return $isB64 ? Base64Url::decode($json[$key]) : $json[$key];
    }
}
