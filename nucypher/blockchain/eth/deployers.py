from constant_sorrow.constants import CONTRACT_NOT_DEPLOYED, NO_DEPLOYER_CONFIGURED, NO_BENEFICIARY
from eth_utils import is_checksum_address
from typing import Tuple, Dict
from web3.contract import Contract

from nucypher.blockchain.eth import constants
from nucypher.blockchain.eth.agents import (
    EthereumContractAgent,
    MinerAgent,
    NucypherTokenAgent,
    PolicyAgent,
    UserEscrowAgent
)
from nucypher.blockchain.eth.interfaces import BlockchainDeployerInterface
from nucypher.blockchain.eth.registry import AllocationRegistry
from .chains import Blockchain


class ContractDeployer:

    agency = NotImplemented
    _contract_name = NotImplemented
    _interface_class = BlockchainDeployerInterface
    __is_proxy = False
    __upgradeable = NotImplemented
    __proxy_deployer = NotImplemented

    class ContractDeploymentError(Exception):
        pass

    class ContractNotDeployed(ContractDeploymentError):
        pass

    def __init__(self, deployer_address: str, blockchain: Blockchain = None) -> None:

        self.blockchain = blockchain or Blockchain.connect()

        self.deployment_receipt = CONTRACT_NOT_DEPLOYED
        self._contract = CONTRACT_NOT_DEPLOYED
        self.__armed = False
        self.__proxy_contract = NotImplemented
        self.__deployer_address = deployer_address

    @property
    def contract_address(self) -> str:
        if self._contract is CONTRACT_NOT_DEPLOYED:
            raise self.ContractNotDeployed
        address = self._contract.address  # type: str
        return address

    @property
    def deployer_address(self):
        return self.__deployer_address

    @property
    def contract(self):
        return self._contract

    @property
    def dispatcher(self):
        return self.__proxy_contract

    @property
    def is_deployed(self) -> bool:
        return bool(self._contract is not CONTRACT_NOT_DEPLOYED)

    @property
    def is_armed(self) -> bool:
        return bool(self.__armed is True)

    def check_ready_to_deploy(self, fail=False, check_arming=False) -> Tuple[bool, list]:
        """
        Iterates through a set of rules required for an ethereum
        contract deployer to be eligible for deployment returning a
        tuple or raising an exception if <fail> is True.

        Returns a tuple containing the boolean readiness result and a list of reasons (if any)
        why the deployer is not ready.

        If fail is set to True, raise a configuration error, instead of returning.
        """

        rules = [
            (self.is_deployed is not True, 'Contract already deployed'),
            (self.deployer_address is not None, 'No deployer address set.'),
            (self.deployer_address is not NO_DEPLOYER_CONFIGURED, 'No deployer address set.'),
        ]

        if check_arming:
            rules.append((self.is_armed is True, 'Contract not armed'))

        disqualifications = list()
        for failed_rule, failure_reason in rules:
            if failed_rule is False:                           # If this rule fails...
                if fail is True:
                    raise self.ContractDeploymentError(failure_reason)
                else:
                    disqualifications.append(failure_reason)   # ... here's why
                    continue

        is_ready = True if len(disqualifications) == 0 else False
        return is_ready, disqualifications

    def _ensure_contract_deployment(self) -> bool:
        """Raises ContractDeploymentError if the contract has not been armed and deployed."""

        if self._contract is CONTRACT_NOT_DEPLOYED:
            class_name = self.__class__.__name__
            message = '{} contract is not deployed. Arm, then deploy.'.format(class_name)
            raise self.ContractDeploymentError(message)

        return True

    def arm(self, abort=True) -> tuple:
        """
        Safety mechanism for ethereum contract deployment

        If the blockchain network being deployed is not in the testchains tuple,
        user interaction is required to enter the arming word.

        If fail_on_abort is True, raise a configuration Error if the user
        incorrectly types the arming_word.

        """
        if self.__armed is True and abort is True:
            raise self.ContractDeploymentError('{} deployer is already armed.'.format(self._contract_name))
        self.__armed, disqualifications = self.check_ready_to_deploy(fail=abort, check_arming=False)
        return self.__armed, disqualifications

    def deploy(self) -> dict:
        """
        Used after arming the deployer;
        Provides for the setup, deployment, and initialization of ethereum smart contracts.
        Emits the configured blockchain network transactions for single contract instance publication.
        """
        raise NotImplementedError

    def make_agent(self) -> EthereumContractAgent:
        agent = self.agency(blockchain=self.blockchain, contract=self._contract)
        return agent


class NucypherTokenDeployer(ContractDeployer):

    agency = NucypherTokenAgent
    _contract_name = agency.registry_contract_name
    __upgradeable = False

    def __init__(self, deployer_address: str, *args, **kwargs) -> None:
        super().__init__(deployer_address=deployer_address, *args, **kwargs)
        self._creator = deployer_address

    def deploy(self) -> dict:
        """
        Deploy and publish the NuCypher Token contract
        to the blockchain network specified in self.blockchain.network.

        The contract must be armed before it can be deployed.
        Deployment can only ever be executed exactly once!
        """
        self.check_ready_to_deploy(fail=True, check_arming=True)

        _contract, deployment_txhash = self.blockchain.interface.deploy_contract(
                                       self._contract_name,
                                       constants.TOKEN_SATURATION)

        self._contract = _contract
        return {'txhash': deployment_txhash}


class DispatcherDeployer(ContractDeployer):
    """
    Ethereum smart contract that acts as a proxy to another ethereum contract,
    used as a means of "dispatching" the correct version of the contract to the client
    """

    _contract_name = 'Dispatcher'
    __is_proxy = True
    __upgradeable = False

    def __init__(self, target_contract: Contract, secret_hash: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_contract = target_contract
        self.secret_hash = secret_hash

    def deploy(self) -> dict:
        args = (self._contract_name, self.target_contract.address, self.secret_hash)
        dispatcher_contract, txhash = self.blockchain.interface.deploy_contract(*args)
        self._contract = dispatcher_contract
        return {'txhash': txhash}


class MinerEscrowDeployer(ContractDeployer):
    """
    Deploys the MinerEscrow ethereum contract to the blockchain.  Depends on NucypherTokenAgent
    """

    agency = MinerAgent
    _contract_name = agency.registry_contract_name
    __upgradeable = True
    __proxy_deployer = DispatcherDeployer

    def __init__(self, secret_hash, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token_agent = NucypherTokenAgent(blockchain=self.blockchain)
        self.secret_hash = secret_hash

    def __check_policy_manager(self):
        result = self.contract.functions.policyManager().call()
        if result is constants.NULL_ADDRESS:
            raise RuntimeError("PolicyManager contract is not initialized.")

    def deploy(self) -> dict:
        """
        Deploy and publish the NuCypher Token contract
        to the blockchain network specified in self.blockchain.network.

        The contract must be armed before it can be deployed.
        Deployment can only ever be executed exactly once!

        Emits the folowing blockchain network transactions:
            - MinerEscrow contract deployment
            - MinerEscrow dispatcher deployment
            - Transfer reward tokens origin -> MinerEscrow contract
            - MinerEscrow contract initialization

        Returns transaction hashes in a dict.
        """

        # Raise if not all-systems-go
        self.check_ready_to_deploy(fail=True, check_arming=True)

        # Build deployment arguments
        origin_args = {'from': self.deployer_address}

        # 1 - Deploy #
        the_escrow_contract, deploy_txhash, = \
            self.blockchain.interface.deploy_contract(self._contract_name,
                                                      self.token_agent.contract_address,
                                                      *map(int, constants.MINING_COEFFICIENT))

        # 2 - Deploy the dispatcher used for updating this contract #
        dispatcher_deployer = DispatcherDeployer(blockchain=self.blockchain,
                                                 target_contract=the_escrow_contract,
                                                 deployer_address=self.deployer_address,
                                                 secret_hash=self.secret_hash)

        dispatcher_deployer.arm()
        dispatcher_deploy_txhashes = dispatcher_deployer.deploy()

        # Cache the dispatcher contract
        dispatcher_contract = dispatcher_deployer.contract
        self.__dispatcher_contract = dispatcher_contract

        # Wrap the escrow contract
        wrapped_escrow_contract = self.blockchain.interface._wrap_contract(dispatcher_contract,
                                                                           target_contract=the_escrow_contract)

        # Switch the contract for the wrapped one
        the_escrow_contract = wrapped_escrow_contract

        # 3 - Transfer tokens to the miner escrow #
        reward_txhash = self.token_agent.contract.functions.transfer(the_escrow_contract.address,
                                                                     constants.TOKEN_SUPPLY).transact(origin_args)

        _reward_receipt = self.blockchain.wait_for_receipt(reward_txhash)

        # 4 - Initialize the Miner Escrow contract
        init_txhash = the_escrow_contract.functions.initialize().transact(origin_args)
        _init_receipt = self.blockchain.wait_for_receipt(init_txhash)

        # Gather the transaction hashes
        deployment_transactions = {'deploy': deploy_txhash,
                                   'dispatcher_deploy': dispatcher_deploy_txhashes['txhash'],
                                   'reward_transfer': reward_txhash,
                                   'initialize': init_txhash}

        # Set the contract and transaction hashes #
        self._contract = the_escrow_contract
        self.deployment_transactions = deployment_transactions
        return deployment_transactions

    def make_agent(self) -> EthereumContractAgent:
        self.__check_policy_manager()  # Ensure the PolicyManager contract has already been initialized
        agent = self.agency(blockchain=self.blockchain, contract=self._contract)
        return agent


class PolicyManagerDeployer(ContractDeployer):
    """
    Depends on MinerAgent and NucypherTokenAgent
    """

    agency = PolicyAgent
    _contract_name = agency.registry_contract_name
    __upgradeable = True
    __proxy_deployer = DispatcherDeployer

    def make_agent(self) -> EthereumContractAgent:
        agent = self.agency(blockchain=self.blockchain, contract=self._contract)
        return agent

    def __init__(self, secret_hash, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token_agent = NucypherTokenAgent(blockchain=self.blockchain)
        self.miner_agent = MinerAgent(blockchain=self.blockchain)
        self.secret_hash = secret_hash

    def deploy(self) -> Dict[str, str]:
        self.check_ready_to_deploy(fail=True, check_arming=True)

        # Creator deploys the policy manager
        policy_manager_contract, deploy_txhash = self.blockchain.interface.deploy_contract(
            self._contract_name, self.miner_agent.contract_address)

        proxy_deployer = self.__proxy_deployer(blockchain=self.blockchain,
                                               target_contract=policy_manager_contract,
                                               deployer_address=self.deployer_address,
                                               secret_hash=self.secret_hash)

        proxy_deployer.arm()
        proxy_deploy_txhashes = proxy_deployer.deploy()

        # Cache the dispatcher contract
        proxy_contract = proxy_deployer.contract
        self.__proxy_contract = proxy_contract

        # Wrap the escrow contract
        wrapped_policy_manager_contract = self.blockchain.interface. \
            _wrap_contract(proxy_contract, target_contract=policy_manager_contract)

        # Switch the contract for the wrapped one
        policy_manager_contract = wrapped_policy_manager_contract

        # Configure the MinerEscrow by setting the PolicyManager
        policy_setter_txhash = self.miner_agent.contract.functions.setPolicyManager(policy_manager_contract.address) \
            .transact({'from': self.deployer_address})

        self.blockchain.wait_for_receipt(policy_setter_txhash)

        # Gather the transaction hashes
        deployment_transactions = {'deployment': deploy_txhash,
                                   'dispatcher_deployment': proxy_deploy_txhashes['txhash'],
                                   'set_policy_manager': policy_setter_txhash}

        self.deployment_transactions = deployment_transactions
        self._contract = policy_manager_contract

        return deployment_transactions


class LibraryLinkerDeployer(ContractDeployer):

    _contract_name = 'UserEscrowLibraryLinker'
    __is_proxy = True
    __upgradeable = False

    def __init__(self, target_contract: Contract, secret_hash: bytes, *args, **kwargs):
        self.target_contract = target_contract
        self.secret_hash = secret_hash
        super().__init__(*args, **kwargs)

    def deploy(self) -> dict:
        linker_args = (self._contract_name, self.target_contract.address, self.secret_hash)
        linker_contract, linker_deployment_txhash = self.blockchain.interface.deploy_contract(*linker_args)
        self._contract = linker_contract
        return {'txhash': linker_deployment_txhash}


class UserEscrowProxyDeployer(ContractDeployer):

    _contract_name = 'UserEscrowProxy'
    __is_proxy = True
    __upgradeable = True
    __proxy_deployer = LibraryLinkerDeployer

    def __init__(self, secret_hash: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token_agent = NucypherTokenAgent(blockchain=self.blockchain)
        self.miner_agent = MinerAgent(blockchain=self.blockchain)
        self.policy_agent = PolicyAgent(blockchain=self.blockchain)
        self.secret_hash = secret_hash

    def __get_state_contract(self) -> str:
        return self.contract.functions.getStateContract()

    def deploy(self) -> dict:

        deployment_transactions = dict()

        # Proxy
        proxy_args = (self._contract_name,
                      self.token_agent.contract_address,
                      self.miner_agent.contract_address,
                      self.policy_agent.contract_address)
        user_escrow_proxy_contract, proxy_deployment_txhash = self.blockchain.interface.deploy_contract(*proxy_args)
        self._contract = user_escrow_proxy_contract
        deployment_transactions['deployment_txhash'] = proxy_deployment_txhash

        # Proxy-Proxy
        proxy_deployer = self.__proxy_deployer(deployer_address=self.deployer_address,
                                               target_contract=user_escrow_proxy_contract,
                                               secret_hash=self.secret_hash)
        proxy_deployer.arm()
        proxy_deployment_txhashes = proxy_deployer.deploy()
        deployment_transactions['proxy_deployment'] = proxy_deployment_txhash

        return deployment_transactions

    @classmethod
    def get_latest_version(cls, blockchain) -> Contract:
        contract = blockchain.interface.get_contract_by_name(name=cls._contract_name,
                                                             proxy_name=cls.__proxy_deployer._contract_name)
        return contract


class UserEscrowDeployer(ContractDeployer):

    agency = UserEscrowAgent
    _contract_name = agency.registry_contract_name
    __proxy_deployer = UserEscrowProxyDeployer
    __allocation_registry = AllocationRegistry

    def __init__(self, allocation_registry: AllocationRegistry = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.token_agent = NucypherTokenAgent(blockchain=self.blockchain)
        self.miner_agent = MinerAgent(blockchain=self.blockchain)
        self.policy_agent = PolicyAgent(blockchain=self.blockchain)
        self.__principal_contract = CONTRACT_NOT_DEPLOYED
        self.__beneficiary_address = NO_BENEFICIARY
        self.__allocation_registry = allocation_registry or self.__allocation_registry()

    def make_agent(self) -> EthereumContractAgent:
        if self.__beneficiary_address is NO_BENEFICIARY:
            raise self.ContractDeploymentError("No beneficiary assigned to {}".format(self.principal_contract.address))
        agent = self.agency(blockchain=self.blockchain,
                            beneficiary=self.__beneficiary_address,
                            allocation_registry=self.__allocation_registry)
        return agent

    @property
    def allocation_registry(self):
        return self.__allocation_registry

    @property
    def principal_contract(self):
        """Directly reference the beneficiary's deployed contract instead of the proxy contracts's interface"""
        if self.__principal_contract is CONTRACT_NOT_DEPLOYED:
            raise self.ContractDeploymentError("{} not deployed".format(self.__class__.__name__))
        return self.__principal_contract

    def assign_beneficiary(self, beneficiary_address: str) -> str:
        """Relinquish ownership of a UserEscrow deployment to the beneficiary"""
        if not is_checksum_address(beneficiary_address):
            raise self.ContractDeploymentError("{} is not a valid checksum address.".format(beneficiary_address))
        txhash = self.principal_contract.functions.transferOwnership(beneficiary_address).transact({'from': self.deployer_address})
        self.blockchain.wait_for_receipt(txhash)
        self.__beneficiary_address = beneficiary_address
        return txhash

    def initial_deposit(self, value: int, duration: int) -> dict:
        """Allocate an amount of tokens with lock time, and transfer ownership to the beneficiary"""
        # Approve
        allocation_transactions = dict()
        approve_txhash = self.token_agent.approve_transfer(amount=value,
                                                           target_address=self.principal_contract.address,
                                                           sender_address=self.deployer_address)
        allocation_transactions['approve'] = approve_txhash
        self.blockchain.wait_for_receipt(approve_txhash)

        # Deposit
        txhash = self.principal_contract.functions.initialDeposit(value, duration).transact({'from': self.deployer_address})
        allocation_transactions['initial_deposit'] = txhash
        self.blockchain.wait_for_receipt(txhash)
        return txhash

    def enroll_principal_contract(self):
        if self.__beneficiary_address is NO_BENEFICIARY:
            raise self.ContractDeploymentError("No beneficiary assigned to {}".format(self.principal_contract.address))
        self.__allocation_registry.enroll(beneficiary_address=self.__beneficiary_address,
                                          contract_address=self.principal_contract.address,
                                          contract_abi=self.principal_contract.abi)

    def deliver(self, value: int, duration: int, beneficiary_address: str) -> dict:
        """
        Transfer allocated tokens and hand-off the contract to the beneficiary.

         Encapsulates three operations:
            - Initial Deposit
            - Transfer Ownership
            - Enroll in Allocation Registry

        """

        deposit_txhash = self.initial_deposit(value=value, duration=duration)
        assign_txhash = self.assign_beneficiary(beneficiary_address=beneficiary_address)
        self.enroll_principal_contract()
        return dict(deposit_txhash=deposit_txhash, assign_txhash=assign_txhash)

    def deploy(self) -> dict:
        """Deploy a new instance of UserEscrow to the blockchain."""

        self.check_ready_to_deploy(fail=True, check_arming=True)

        deployment_transactions = dict()
        proxy_contract = self.__proxy_deployer.get_latest_version(blockchain=self.blockchain)

        args = (self._contract_name, proxy_contract.address, self.token_agent.contract_address)
        user_escrow_contract, deploy_txhash = self.blockchain.interface.deploy_contract(*args, enroll=False)
        self.__principal_contract = user_escrow_contract
        deployment_transactions['deploy_user_escrow'] = deploy_txhash

        self._contract = user_escrow_contract

        return deployment_transactions
