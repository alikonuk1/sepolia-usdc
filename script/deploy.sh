source .env

forge script script/mockUSDC.s.sol:mockUSDCScript --chain-id 11155111 --rpc-url https://rpc.ankr.com/eth_sepolia \
    --broadcast --etherscan-api-key $ETHERSCAN_API_KEY \
    --verify -vvvv