from pydantic import BaseModel, Field
from typing import Optional, List, Dict


class ParentModel(BaseModel):
    accountId: Optional[str] = Field(
        default="", description="Account Number for Money Manager Client"
    )
    isMChild: bool = Field(
        default=False, description="Returns if this is a Multiplex Child Account"
    )
    isMParent: bool = Field(
        default=False, description="Returns if this is a Multiplex Parent Account"
    )
    isMultiplex: bool = Field(
        default=False, description="Indicates if this is a Multiplex Account"
    )
    mmc: List[str] = Field(
        default_factory=list, description="Returns the Money Manager Client Account"
    )


class AccountModel(BaseModel):
    id: str = Field(
        ..., description="The account ID for which account should place the order."
    )
    accountId: str = Field(
        ..., description="The account ID for which account should place the order."
    )
    accountVan: str = Field(
        ..., description="The account alias for which account should place the order."
    )
    accountTitle: str = Field(..., description="Title of the account.")
    displayName: str = Field(
        ..., description="The account ID for which account should place the order."
    )
    accountAlias: Optional[str] = Field(
        None,
        description="User customizable account alias. Refer to Configure Account Alias for details.",
    )
    accountStatus: int = Field(
        ..., description="When the account was opened, in Unix time."
    )
    currency: str = Field(..., description="Base currency of the account.")
    type: str = Field(..., description="Account Type.")
    tradingType: str = Field(..., description="Account trading structure.")
    businessType: str = Field(
        ..., description="Returns the organizational structure of the account."
    )
    ibEntity: str = Field(
        ...,
        description="Returns the entity of Interactive Brokers the account is tied to.",
    )
    faclient: bool = Field(
        default=False,
        description="Indicates if an account is a sub-account to a Financial Advisor.",
    )
    clearingStatus: str = Field(
        ...,
        description="Status of the Account. Potential Values: O: Open; P or N: Pending; A: Abandoned; R: Rejected; C: Closed.",
    )
    covestor: bool = Field(
        default=False, description="Indicates if the account is a Covestor Account."
    )
    noClientTrading: bool = Field(
        default=False, description="Indicates if the client account may trade."
    )
    trackVirtualFXPortfolio: bool = Field(
        default=False,
        description="Indicates if the account is tracking Virtual FX or not.",
    )
    parent: ParentModel = Field(
        ..., description="Parent account information, if applicable."
    )
    desc: str = Field(
        ...,
        description='Returns an account description in the format: "accountId - accountAlias".',
    )

    def __str__(self):
        return (
            f"Account ID: {self.accountId}\n"
            f"Alias: {self.accountAlias or 'N/A'}\n"
            f"Title: {self.accountTitle}\n"
            f"Business Type: {self.businessType}\n"
            f"Currency: {self.currency}\n"
            f"Trading Type: {self.tradingType}\n"
            f"Clearing Status: {self.clearingStatus}\n"
            f"Parent Account ID: {self.parent.accountId or 'N/A'}\n"
            "-------------------------------------------"
        )


class MetaModel(BaseModel):
    total: int = Field(None, description="Total number of items")
    pageSize: int = Field(None, description="Number of items per page")
    pageNum: int = Field(None, description="Current page number")


class GenericPaginatedResponseModel(BaseModel):
    metadata: MetaModel = Field(..., description="Metadata")


class SubAccounts2ResponseModel(GenericPaginatedResponseModel):
    subaccounts: List[AccountModel] = Field(..., description="List of sub accounts")


class PositionModel(BaseModel):
    acctId: Optional[str] = Field(None, description="Account ID.")
    conid: Optional[int] = Field(
        None, description="Returns the contract ID of the position."
    )
    contractDesc: Optional[str] = Field(
        None, description="Returns the local symbol of the order."
    )
    position: Optional[float] = Field(
        None, description="Returns the total size of the position."
    )
    mktPrice: Optional[float] = Field(
        None, description="Returns the current market price of each share."
    )
    mktValue: Optional[float] = Field(
        None, description="Returns the total value of the order."
    )
    avgCost: Optional[float] = Field(
        None,
        description="Returns the average cost of each share in the position times the multiplier.",
    )
    avgPrice: Optional[float] = Field(
        None,
        description="Returns the average cost of each share in the position when purchased.",
    )
    realizedPnl: Optional[float] = Field(
        None, description="Returns the total profit made today through trades."
    )
    unrealizedPnl: Optional[float] = Field(
        None, description="Returns the total potential profit if you were to trade."
    )
    exchs: Optional[str] = Field(
        None, description="Deprecated value. Always returns null."
    )
    currency: Optional[str] = Field(
        None, description="Returns the traded currency for the contract."
    )
    expiry: Optional[str] = Field(
        None,
        description="Returns the expiry of the contract. Returns null for non-expiry instruments.",
    )
    putOrCall: Optional[str] = Field(
        None, description="Returns if the contract is a Put or Call option."
    )
    multiplier: Optional[float] = Field(
        None, description="Returns the contract multiplier."
    )
    strike: Optional[float] = Field(
        None, description="Returns the strike of the contract."
    )
    assetClass: Optional[str] = Field(
        None, description="Returns the asset class or security type of the contract."
    )
    undConid: Optional[int] = Field(
        None, description="Returns the contract’s underlyer."
    )
    model: Optional[str] = Field(None, description="The model for the position.")
    isLastToLoq: Optional[bool] = Field(
        None, description="Returns if the contract is last to liquidate"
    )
    timestamp: Optional[int] = Field(
        None, description="Returns the epoch timestamp of the portfolio request"
    )
    sector: Optional[str] = Field(
        None, description="Returns the sector of the contract."
    )
    group: Optional[str] = Field(
        None,
        description="Returns the group or industry the contract is affilated with.",
    )

    def __str__(self) -> str:
        return (
            f"Position(acctId={self.acctId}, conid={self.conid}, contractDesc={self.contractDesc}, "
            f"position={self.position}, mktPrice={self.mktPrice}, mktValue={self.mktValue}, "
            f"currency={self.currency}, avgCost={self.avgCost}, avgPrice={self.avgPrice}, "
            f"realizedPnl={self.realizedPnl}, unrealizedPnl={self.unrealizedPnl}, "
            f"assetClass={self.assetClass}, undConid={self.undConid}, model={self.model})"
        )


class SwitchAccountResponseModel(BaseModel):
    set: bool = Field(..., description="Returns if the account was successfully set.")
    acctId: str = Field(..., description="Returns the account ID that was set.")


class ServerInfoModel(BaseModel):
    serverName: Optional[str] = Field(default="", description="Server Name")
    serverVersion: Optional[str] = Field(default="", description="Server Version")


class InitBrokerageSessionResponseModel(BaseModel):
    authenticated: bool = Field(
        default=False, description="Indicates if the client is authenticated."
    )
    competing: bool = Field(
        default=False, description="Indicates if the client is competing."
    )
    connected: bool = Field(
        default=False, description="Indicates if the client is connected."
    )
    message: Optional[str] = Field(default="")
    MAC: str = Field(default="", description="MAC Address")
    serverInfo: ServerInfoModel = Field(..., description="Server Information")


class StatusResponseModel(BaseModel):
    status: str = Field(..., description="Status of the request.")


class CurrencyEntryModel(BaseModel):
    symbol: str
    conid: int
    ccyPair: str


class AccountDetailModel(BaseModel):
    rowType: int = Field(
        ...,
        description="Returns the positional value of the returned account. Always returns 1 for individual accounts.",
    )
    dpl: float = Field(..., description="Daily PnL for the specified account profile.")
    nl: float = Field(
        ..., description="Net Liquidity for the specified account profile."
    )
    upl: float = Field(
        ..., description="Unrealized PnL for the specified account profile."
    )
    el: float = Field(
        ..., description="Excess Liquidity for the specified account profile."
    )
    mv: float = Field(
        ..., description="Margin value for the specified account profile."
    )


class UpdatedPnLModel(BaseModel):
    upnl: Dict[str, AccountDetailModel] = Field(
        ...,
        description="Refers to “updated PnL”. Holds a json object of key-value paired account pnl details.",
    )


class OrderDetailModel(BaseModel):
    acct: str = Field(..., description="Returns the accountID for the submitted order.")
    conidex: str = Field(
        ..., description="Returns the contract identifier for the order."
    )
    conid: int = Field(
        ..., description="Returns the contract identifier for the order."
    )
    account: str = Field(
        ..., description="Returns the accountID for the submitted order."
    )
    orderId: int = Field(
        ..., description="Returns the local order identifier of the order."
    )
    cashCcy: str = Field(..., description="Returns the currency used for the order.")
    sizeAndFills: str = Field(
        ...,
        description="Returns the size of the order and how much of it has been filled.",
    )
    orderDesc: str = Field(
        ...,
        description="Returns the description of the order including the side, size, order type, price, and tif.",
    )
    description1: str = Field(..., description="Returns the local symbol of the order.")
    ticker: str = Field(..., description="Returns the ticker symbol for the order.")
    secType: str = Field(..., description="Returns the security type for the order.")
    listingExchange: str = Field(
        ..., description="Returns the primary listing exchange of the order."
    )
    remainingQuantity: float = Field(
        ..., description="Returns the remaining size for the order to fill."
    )
    filledQuantity: float = Field(
        ..., description="Returns the size of the order already filled."
    )
    totalSize: float = Field(..., description="Returns the total size of the order.")
    companyName: str = Field(..., description="Returns the company long name.")
    status: str = Field(..., description="Returns the current status of the order.")
    order_ccp_status: str = Field(
        ..., description="Returns the current status of the order."
    )
    avgPrice: str = Field(
        ..., description="Returns the average price of execution for the order."
    )
    origOrderType: str = Field(
        ...,
        description="Returns the original order type of the order, whether or not the type has been changed.",
    )
    supportsTaxOpt: str = Field(
        ..., description="Returns if the order is supported by the Tax Optimizer."
    )
    lastExecutionTime: str = Field(
        ...,
        description="Returns the datetime of the order’s most recent execution. Time returned is based on UTC timezone. Value Format: YYMMDDHHmmss",
    )
    orderType: str = Field(
        ...,
        description="Returns the current order type, or the order at the time of execution.",
    )
    bgColor: str = Field(..., description="Internal use only.")
    fgColor: str = Field(..., description="Internal use only.")
    order_ref: str = Field(
        ...,
        description="User defined string used to identify the order. Value is set using “cOID” field while placing an order.",
    )
    timeInForce: str = Field(
        ..., description="Returns the time in force (tif) of the order."
    )
    lastExecutionTime_r: int = Field(
        ...,
        description="Returns the epoch time of the most recent execution on the order.",
    )
    side: str = Field(..., description="Returns the side of the order.")


class OrdersModel(BaseModel):
    orders: List[OrderDetailModel] = Field(..., description="List of Orders")
    snapshot: bool = Field(
        ..., description="Returns if the data is a snapshot of the account’s orders."
    )
