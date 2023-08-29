// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "lib/openzeppelin-contracts/contracts/utils/Counters.sol";

// It is not possible to override the EIP712 version of
// @openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol
// so it is copy-pasted below with the version "2" to imitate USDC

/**
 * @dev Implementation of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 *
 * _Available since v3.4._
 */
abstract contract ERC20Permit is ERC20, IERC20Permit, EIP712 {
    using Counters for Counters.Counter;

    mapping(address => Counters.Counter) private _nonces;

    // solhint-disable-next-line var-name-mixedcase
    bytes32 private constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    /**
     * @dev In previous versions `_PERMIT_TYPEHASH` was declared as `immutable`.
     * However, to ensure consistency with the upgradeable transpiler, we will continue
     * to reserve a slot.
     * @custom:oz-renamed-from _PERMIT_TYPEHASH
     */
    // solhint-disable-next-line var-name-mixedcase
    bytes32 private _PERMIT_TYPEHASH_DEPRECATED_SLOT;

    /**
     * @dev Initializes the {EIP712} domain separator using the `name` parameter, and setting `version` to `"1"`.
     *
     * It's a good idea to use the same `name` that is defined as the ERC20 token name.
     */
    constructor(string memory name) EIP712(name, "2") {}

    /**
     * @dev See {IERC20Permit-permit}.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
        virtual
        override
    {
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(abi.encode(_PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, "ERC20Permit: invalid signature");

        _approve(owner, spender, value);
    }

    /**
     * @dev See {IERC20Permit-nonces}.
     */
    function nonces(address owner) public view virtual override returns (uint256) {
        return _nonces[owner].current();
    }

    /**
     * @dev See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev "Consume a nonce": return the current value and increment.
     *
     * _Available since v4.1._
     */
    function _useNonce(address owner) internal virtual returns (uint256 current) {
        Counters.Counter storage nonce = _nonces[owner];
        current = nonce.current();
        nonce.increment();
    }
}

contract mockUSDC is ERC20Permit {
    using ECDSA for bytes32;

    bytes32 internal constant templateId =
        0x4385954e058fbe6b6a744f32a4f89d67aad099f8fb8b23e7ea8dd366ae88151d;
    address internal constant airnode =
        0xf64C92bb13a9Ac7EE3448cD45398A33cE85634F1;
    address public treasury;

    mapping(address => bool) public isWithdrawer;
    
    constructor() ERC20("SepoliaUsdc", "testUSDC") ERC20Permit("SepoliaUsdc") {
        isWithdrawer[msg.sender] = true;
    }

    modifier onlyWithdrawer() {
        require(isWithdrawer[msg.sender], "Forbidden");
        _;
    }

    function mint(
        address recipient,
        uint256 timestamp,
        bytes calldata data,
        bytes calldata signature
    ) external payable {
        require(msg.value > 0, "Must send some ETH!");
        require(data.length == 32, "Data length is not correct!");
        require(!(timestamp > block.timestamp || timestamp + 60 <= block.timestamp), "Out of date price");
        require(
            (keccak256(abi.encodePacked(templateId, timestamp, data))).recover(signature) == airnode,
            "Signature Mismatch"
        );

        int256 price = abi.decode(data, (int256));

        uint256 tokensToMint = (msg.value * uint256(price)) / (10 ** 12);

        require(tokensToMint > 0, "Sent ETH amount too small to mint any tokens.");

        _mint(recipient, tokensToMint);
    }

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }

    function addWithdrawer(address _withdrawer) external onlyWithdrawer {
        isWithdrawer[_withdrawer] = true;
    }

    function withdraw() external onlyWithdrawer {
        (bool sent,) = msg.sender.call{value: address(this).balance}("");
        require(sent, "Failed to send Ether");
    }
}
