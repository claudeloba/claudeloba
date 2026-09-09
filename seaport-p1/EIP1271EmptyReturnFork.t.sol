// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ConsiderationInterface} from "seaport-types/src/interfaces/ConsiderationInterface.sol";
import {ItemType, OrderType} from "seaport-types/src/lib/ConsiderationEnums.sol";
import {
    ConsiderationItem,
    OfferItem,
    Order,
    OrderComponents,
    OrderParameters
} from "seaport-types/src/lib/ConsiderationStructs.sol";

contract TestERC20For1271 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool)
    {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ALLOWANCE");
        require(balanceOf[from] >= amount, "BALANCE");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev This contract deliberately has no EIP-1271 implementation. Its fallback
/// succeeds and returns zero bytes, a common proxy/receiver behavior.
contract EmptyReturnVault {
    constructor(TestERC20For1271 token, address seaport) {
        token.approve(seaport, type(uint256).max);
    }

    fallback() external payable {}
    receive() external payable {}
}

contract RevertingFallbackVault {
    constructor(TestERC20For1271 token, address seaport) {
        token.approve(seaport, type(uint256).max);
    }

    fallback() external payable {
        revert("NO_1271");
    }
}

contract EIP1271EmptyReturnForkTest is Test {
    address internal constant SEAPORT =
        0x0000000000000068F116a894984e2DB1123eB395;
    bytes32 internal constant EXPECTED_RUNTIME_HASH =
        0x74499ac0cce14428e4b41541d5e44f28f5a6882a1051d0118867c2a93cd5aec0;

    uint256 internal constant ATTACKER_PK =
        0xA11CE00000000000000000000000000000000000000000000000000000000001;

    ConsiderationInterface internal seaport;
    TestERC20For1271 internal token;
    address internal attacker;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), 20_000_000);
        assertEq(block.chainid, 1, "CHAIN");
        assertEq(SEAPORT.codehash, EXPECTED_RUNTIME_HASH, "RUNTIME_HASH");
        assertEq(SEAPORT.code.length, 23_981, "RUNTIME_LENGTH");

        seaport = ConsiderationInterface(SEAPORT);
        (string memory version,,) = seaport.information();
        assertEq(keccak256(bytes(version)), keccak256(bytes("1.6")), "VERSION");

        token = new TestERC20For1271();
        attacker = vm.addr(ATTACKER_PK);
    }

    function testEmptySuccessfulFallbackMustNotForgeEIP1271Authorization() public {
        EmptyReturnVault vault = new EmptyReturnVault(token, SEAPORT);
        token.mint(address(vault), 100 ether);

        Order memory order = _order(address(vault), 100 ether, 0x12710001);
        order.signature = _signatureByAttacker(order.parameters);

        uint256 victimBefore = token.balanceOf(address(vault));
        uint256 attackerBefore = token.balanceOf(attacker);

        vm.prank(attacker);
        vm.expectRevert();
        seaport.fulfillOrder(order, bytes32(0));

        assertEq(token.balanceOf(address(vault)), victimBefore, "UNAUTHORIZED_VICTIM_DEBIT");
        assertEq(token.balanceOf(attacker), attackerBefore, "UNAUTHORIZED_ATTACKER_GAIN");
    }

    function testRevertingFallbackControlRejects() public {
        RevertingFallbackVault vault = new RevertingFallbackVault(token, SEAPORT);
        token.mint(address(vault), 100 ether);

        Order memory order = _order(address(vault), 100 ether, 0x12710002);
        order.signature = _signatureByAttacker(order.parameters);

        vm.prank(attacker);
        vm.expectRevert();
        seaport.fulfillOrder(order, bytes32(0));
        assertEq(token.balanceOf(address(vault)), 100 ether);
        assertEq(token.balanceOf(attacker), 0);
    }

    function _order(address offerer, uint256 amount, uint256 salt)
        internal
        view
        returns (Order memory order)
    {
        OfferItem[] memory offer = new OfferItem[](1);
        offer[0] = OfferItem({
            itemType: ItemType.ERC20,
            token: address(token),
            identifierOrCriteria: 0,
            startAmount: amount,
            endAmount: amount
        });
        ConsiderationItem[] memory consideration = new ConsiderationItem[](0);
        order.parameters = OrderParameters({
            offerer: offerer,
            zone: address(0),
            offer: offer,
            consideration: consideration,
            orderType: OrderType.FULL_OPEN,
            startTime: 0,
            endTime: type(uint256).max,
            zoneHash: bytes32(0),
            salt: salt,
            conduitKey: bytes32(0),
            totalOriginalConsiderationItems: 0
        });
    }

    function _signatureByAttacker(OrderParameters memory p)
        internal
        view
        returns (bytes memory)
    {
        OrderComponents memory c = OrderComponents({
            offerer: p.offerer,
            zone: p.zone,
            offer: p.offer,
            consideration: p.consideration,
            orderType: p.orderType,
            startTime: p.startTime,
            endTime: p.endTime,
            zoneHash: p.zoneHash,
            salt: p.salt,
            conduitKey: p.conduitKey,
            counter: seaport.getCounter(p.offerer)
        });
        bytes32 orderHash = seaport.getOrderHash(c);
        (, bytes32 domainSeparator,) = seaport.information();
        bytes32 digest = keccak256(
            abi.encodePacked(bytes2(0x1901), domainSeparator, orderHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_PK, digest);
        return abi.encodePacked(r, s, v);
    }
}
