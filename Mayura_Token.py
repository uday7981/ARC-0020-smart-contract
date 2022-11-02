from ast import Is

import urllib
from typing import Final
from pyteal import (
    Reject,
    abi,
    TealType,
    Subroutine,
    Itob,
    Assert,
    Global,
    Bytes,
    Int,
    Seq,
    Txn,
    If,
    And,
    InnerTxnBuilder,
    ScratchVar,
    TxnField,
    TxnType,
    Not,
    WideRatio,
    Concat,
)

from beaker import (
    Application,
    ApplicationStateValue,
    DynamicAccountStateValue,
    Authorize,
    external,
    internal,
    create,
    update,
    delete,
    opt_in,
)

webUrl = urllib.request.urlopen("https://github.com/algorandlabs/smart-asa/blob/main/smart_asa_asc.py")


class MayuraToken():
    class Offer(abi.NamedTuple):
        auth_address: abi.Field[abi.Address]
        amount: abi.Field[abi.Uint64]

    class TokenPolicy(abi.NamedTuple):
        receiver: abi.Field[abi.Address]
        basis: abi.Field[abi.Uint64]

    administrator: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.bytes, key=Bytes("admin"), default=Global.creator_address()
    )

    token_basis: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.uint64
    )

    Perks_receiver: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.bytes
    )

    offers: Final[DynamicAccountStateValue] = DynamicAccountStateValue(
        stack_type=TealType.bytes,
        max_keys=14,
        key_gen=Subroutine(TealType.bytes)(lambda x: Itob(x)),
    )

    
    _basis_point_multiplier: Final[int] = 100 * 100
    basis_point_multiplier: Final[Int] = Int(_basis_point_multiplier)

   

    @create
    def create(self):
        return self.initialize_application_state()

    @update
    def update(self):
        return Assert(Txn.sender() == self.administrator)

    @delete
    def delete(self):
        return Assert(Txn.sender() == self.administrator)

    @opt_in
    def opt_in(self):
        return self.initialize_account_state()

   

    @external(authorize=Authorize.only(administrator))
    def set_administrator(self, new_admin: abi.Address):
       
        return self.administrator.set(new_admin.get())

    @external(authorize=Authorize.only(administrator))
    def set_policy(self, token_policy: TokenPolicy):
        
        return Seq(
            (basis := abi.Uint64()).set(token_policy.basis),
            (rcv := abi.Address()).set(token_policy.receiver),
            Assert(basis.get() <= self.basis_point_multiplier),
            self.token_basis.set(basis.get()),
            self.Perks_receiver.set(rcv.encode()),
        )

    @external(authorize=Authorize.only(administrator))
    def set_payment_asset(self, payment_asset: abi.Asset, is_allowed: abi.Bool):
        return Seq(
            bal := payment_asset.holding(self.address).balance(),
            creator := payment_asset.params().creator_address(),
            If(And(is_allowed.get(), Not(bal.hasValue())))
            .Then(
               
                InnerTxnBuilder.Execute(
                    {
                        TxnField.type_enum: TxnType.AssetTransfer,
                        TxnField.xfer_asset: payment_asset.asset_id(),
                        TxnField.asset_amount: Int(0),
                        TxnField.fee: Int(0),
                        TxnField.asset_receiver: self.address,
                    }
                )
            )
            .ElseIf(And(Not(is_allowed.get()), bal.hasValue()))
            .Then(
               
                InnerTxnBuilder.Execute(
                    {
                        TxnField.type_enum: TxnType.AssetTransfer,
                        TxnField.xfer_asset: payment_asset.asset_id(),
                        TxnField.asset_amount: Int(0),
                        TxnField.fee: Int(0),
                        TxnField.asset_close_to: creator.value(),
                        TxnField.asset_receiver: creator.value(),
                    }
                )
            )
            .Else(Reject()),
        )

    @external
    def transfer_algo_payment(
        self,
        personalized_token: abi.Asset,
        personalized_token_amount: abi.Uint64,
        owner: abi.Account,
        buyer: abi.Account,
        perks_receiver: abi.Account,
        payment_txn: abi.PaymentTransaction,
        offered_amt: abi.Uint64,
    ):
       
        valid_transfer_group = Seq(
            (offer := abi.make(self.Offer)).decode(
                self.offers[personalized_token.asset_id()][owner.address()]
            ),
            (offer_amt := abi.Uint64()).set(offer.amount),
            (offer_auth := abi.Address()).set(offer.auth_address),
            Assert(
                Global.group_size() == Int(2),
               
                Txn.sender() == offer_auth.get(),
                
                personalized_token_amount.get() <= offer_amt.get(),
                
                payment_txn.get().receiver() == self.address,
                perks_receiver.address() == self.Perks_receiver,
            ),
        )

        return Seq(
            
            valid_transfer_group,
           
            self.do_pay_algos(
                payment_txn.get().amount(),
                owner.address(),
                perks_receiver.address(),
                self.royalty_basis,
            ),
            
            self.do_move_asset(
                personalized_token.asset_id(),
                owner.address(),
                buyer.address(),
                personalized_token_amount.get(),
            ),
            
            self.do_update_offered(
                owner.address(),
                personalized_token.asset_id(),
                offer_auth.get(),
                offer_amt.get() - personalized_token_amount.get(),
                Txn.sender(),
                offered_amt.get(),
            ),
        )

    @external
    def transfer_asset_payment(
        self,
        personalized_token: abi.Asset,
        personalized_token_amount: abi.Uint64,
        owner: abi.Account,
        buyer: abi.Account,
        perks_receiver: abi.Account,
        payment_txn: abi.AssetTransferTransaction,
        payment_asset: abi.Asset,
        offered_amt: abi.Uint64,
    ):
       
        valid_transfer_group = Seq(
            
            (offer := abi.make(self.Offer)).decode(
                self.offers[personalized_token.asset_id()][owner.address()]
            ),
            (offer_amt := abi.Uint64()).set(offer.amount),
            (offer_auth := abi.Address()).set(offer.auth_address),
            Assert(
                Global.group_size() == Int(2),
                
                Txn.sender() == offer_auth.get(),
                
                payment_txn.get().sender() == offer_auth.get(),

                personalized_token_amount.get() <= offer_amt.get(),
               
                payment_txn.get().xfer_asset() == payment_asset.asset_id(),
                
                payment_txn.get().asset_receiver() == self.address,
                 perks_receiver.address() == self.Perks_receiver,
            ),
        )

        return Seq(
           
            valid_transfer_group,
            self.do_pay_assets(
                payment_txn.get().xfer_asset(),
                payment_txn.get().asset_amount(),
                owner.address(),
            ),
            
            self.do_move_asset(
                personalized_token.asset_id(),
                owner.address(),
                buyer.address(),
                personalized_token_amount.get(),
            ),
            
            self.do_update_offered(
                owner.address(),
                personalized_token.asset_id(),
                offer_auth.get(),
                offer_amt.get() - personalized_token_amount.get(),
                Txn.sender(),
                offered_amt.get(),
            ),
        )

    @external
    def offer(
        self,
        personalized_token: abi.Asset,
        offer: Offer,
        previous_offer: Offer,
    ):
        
        return Seq(
            (offer_amt := abi.Uint64()).set(offer.amount),
            (offer_auth := abi.Address()).set(offer.auth_address),
            (prev_amt := abi.Uint64()).set(previous_offer.amount),
            (prev_auth := abi.Address()).set(previous_offer.auth_address),
            bal := personalized_token.holding(Txn.sender()).balance(),
            cb := personalized_token.params().clawback_address(),
            Assert(
               
                bal.value() >= offer_amt.get(),
                
                cb.value() == self.address,
                
            ),
           
            self.do_update_offered(
                Txn.sender(),
                personalized_token.asset_id(),
                offer_auth.get(),
                offer_amt.get(),
                prev_auth.get(),
                prev_amt.get(),
            ),
        )

    @external
    def Token_free_move(
        self,
        personalized_token: abi.Asset,
        personalized_token_amount: abi.Uint64,
        owner: abi.Account,
        receiver: abi.Account,
        offered_amt: abi.Uint64,
    ):
        
        return Seq(
            (offer := abi.make(self.Offer)).decode(
                self.offers[ personalized_token.asset_id()][owner.address()]
            ),
            (curr_offer_amt := abi.Uint64()).set(offer.amount),
            (curr_offer_auth := abi.Address()).set(offer.auth_address),
           
            Assert(
                curr_offer_amt.get() == offered_amt.get(),
                curr_offer_amt.get() >= personalized_token_amount.get(),
                curr_offer_auth.get() == Txn.sender(),
            ),
            
            self.do_update_offered(
                owner.address(),
                personalized_token.asset_id(),
                Bytes(""),
                Int(0),
                curr_offer_auth.get(),
                curr_offer_amt.get(),
            ),
            
            self.do_move_asset(
                personalized_token.asset_id(),
                owner.address(),
                receiver.address(),
                personalized_token_amount.get(),
            ),
        )

   

    @external(read_only=True)
    def get_offer(
        self, personalized_token: abi.Uint64, owner: abi.Account, *, output: Offer
    ):
        
        return output.decode(
            self.offers[personalized_token.get()][owner.address()].get_must()
        )

    @external(read_only=True)
    def get_policy(self, *, output: TokenPolicy):
       
        return Seq(
            (basis := abi.Uint64()).set(self.token_basis.get_must()),
            (rcv := abi.Address()).set(self.Perks_receiver.get_must()),
            output.set(rcv, basis),
        )

    @external(read_only=True)
    def get_administrator(self, *, output: abi.Address):
       
        return output.decode(self.administrator)

    

    def compute_Token_amount(self, payment_amt, token_basis):
        return WideRatio([payment_amt, token_basis], [self.basis_point_multiplier])

    
    @internal(TealType.none)
    def do_pay_assets(self, purchase_asset_id, purchase_amt, owner):
        personalized_token_amt = ScratchVar()
        return Seq(
            personalized_token_amt.store(
                self.compute_Token_amount(purchase_amt, self.token_basis)
            ),
            InnerTxnBuilder.Begin(),
            InnerTxnBuilder.SetFields(
                {
                    TxnField.type_enum: TxnType.AssetTransfer,
                    TxnField.xfer_asset: purchase_asset_id,
                    TxnField.asset_amount: purchase_amt - personalized_token_amt.load(),
                    TxnField.asset_receiver: owner,
                    TxnField.fee: Int(0),
                }
            ),
            If(
                personalized_token_amt.load() > Int(0),
                Seq(
                    InnerTxnBuilder.Next(),
                    InnerTxnBuilder.SetFields(
                        {
                            TxnField.type_enum: TxnType.AssetTransfer,
                            TxnField.xfer_asset: purchase_asset_id,
                            TxnField.asset_amount: personalized_token_amt.load(),
                            TxnField.asset_receiver: self.Perks_receiver,
                            TxnField.fee: Int(0),
                        }
                    ),
                ),
            ),
            InnerTxnBuilder.Submit(),
        )

    @internal(TealType.none)
    def do_pay_algos(self, purchase_amt, owner, perks_receiver, token_basis):
        token_amt = ScratchVar()
        return Seq(
            token_amt.store(self.compute_token_amount(purchase_amt, token_basis)),
            InnerTxnBuilder.Begin(),
            InnerTxnBuilder.SetFields(
                {
                    TxnField.type_enum: TxnType.Payment,
                    TxnField.amount: purchase_amt - token_amt.load(),
                    TxnField.receiver: owner,
                    TxnField.fee: Int(0),
                }
            ),
            If(
                token_amt.load() > Int(0),
                Seq(
                    InnerTxnBuilder.Next(),
                    InnerTxnBuilder.SetFields(
                        {
                            TxnField.type_enum: TxnType.Payment,
                            TxnField.amount: token_amt.load(),
                            TxnField.receiver: perks_receiver,
                            TxnField.fee: Int(0),
                        }
                    ),
                ),
            ),
            InnerTxnBuilder.Submit(),
        )

    @internal(TealType.none)
    def do_move_asset(asset_id, from_addr, to_addr, asset_amt):
        return InnerTxnBuilder.Execute(
            {
                TxnField.type_enum: TxnType.AssetTransfer,
                TxnField.xfer_asset: asset_id,
                TxnField.asset_amount: asset_amt,
                TxnField.asset_sender: from_addr,
                TxnField.asset_receiver: to_addr,
                TxnField.fee: Int(0),
            }
        )

    @internal(TealType.none)
    def do_update_offered(self, acct, asset, auth, amt, prev_auth, prev_amt):
        return Seq(
            previous := self.offers[asset][acct].get_maybe(),
            
            If(
                previous.hasValue(),
                Seq(
                    (prev_offer := abi.make(self.Offer)).decode(previous.value()),
                    prev_offer.amount.use(lambda amt: Assert(amt.get() == prev_amt)),
                    prev_offer.auth_address.use(
                        lambda addr: Assert(addr.get() == prev_auth)
                    ),
                ),
                Assert(prev_amt == Int(0), prev_auth == Global.zero_address()),
            ),
           
            If(
                amt > Int(0),
              
                self.offers[asset][acct].set(Concat(auth, Itob(amt))),
                self.offers[asset][acct].delete(),
            ),
        )


if __name__ == "__main__":
    import json

    MayuraToken = MayuraToken()

    print(MayuraToken.approval_program)
    print(MayuraToken.clear_program)
    print(json.dumps(MayuraToken.contract.dictify()))

