#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame::prelude::*;

    #[derive(Clone, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct Credential<T: Config> {
        pub remark: BoundedVec<u8, T::MaxRemarkLen>,
        pub public_key: [u8; 32],
        pub nonce: T::Nonce,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type MaxRemarkLen: Get<u32>;
        #[pallet::constant]
        type AliceAccountId: Get<Self::AccountId>;
        #[pallet::constant]
        type BobAccountId: Get<Self::AccountId>;
    }

    /// 存储一：正式的凭证
    #[pallet::storage]
    pub type Credentials<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Credential<T>, OptionQuery>;

    /// 存储二：待审批的申请 [账户ID -> 备注内容]
    #[pallet::storage]
    pub type PendingRequests<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, BoundedVec<u8, T::MaxRemarkLen>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// 发起了申请
        RequestCreated { who: T::AccountId },
        /// 申请被批准
        RequestApproved { who: T::AccountId, approved_by: T::AccountId },
        /// 凭证颁发成功 (针对特权账户)
        CredentialIssued { who: T::AccountId },
        /// 凭证注销
        CredentialRevoked { who: T::AccountId },
    }

    #[pallet::error]
    pub enum Error<T> {
        RemarkTooLong,
        CredentialAlreadyExists,
        RequestAlreadyExists,
        RequestNotFound,
        NotAuthorized, // 不是 Alice 或 Bob，无权审批
        CredentialNotFound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// 1. 提交申请 (任何人都可以调用)
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn apply_for_credential(origin: OriginFor<T>, remark: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // 检查是否已有凭证
            ensure!(!Credentials::<T>::contains_key(&who), Error::<T>::CredentialAlreadyExists);

            // 如果是 Alice 或 Bob 本人，直接颁发，不需要进申请列表
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();
            if who == alice || who == bob {
                return Self::do_issue(&who, remark);
            }

            // 检查是否已有申请在排队
            ensure!(!PendingRequests::<T>::contains_key(&who), Error::<T>::RequestAlreadyExists);

            let bounded_remark: BoundedVec<u8, T::MaxRemarkLen> = 
                remark.try_into().map_err(|_| Error::<T>::RemarkTooLong)?;

            // 放入待审批列表
            PendingRequests::<T>::insert(&who, bounded_remark);
            Self::deposit_event(Event::RequestCreated { who });

            Ok(())
        }

        /// 2. 审批申请 (只有 Alice 或 Bob 能调用)
        #[pallet::call_index(1)]
        #[pallet::weight(0)]
        pub fn approve_credential(origin: OriginFor<T>, target_user: T::AccountId) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // 只有特权账户能审批
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();
            ensure!(sender == alice || sender == bob, Error::<T>::NotAuthorized);

            // 从申请列表中拿出备注
            let remark_vec = PendingRequests::<T>::get(&target_user)
                .ok_or(Error::<T>::RequestNotFound)?
                .to_vec();

            // 正式颁发凭证
            Self::do_issue(&target_user, remark_vec)?;

            // 从待审批列表中删除
            PendingRequests::<T>::remove(&target_user);

            Self::deposit_event(Event::RequestApproved { 
                who: target_user, 
                approved_by: sender 
            });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(0)]
        pub fn revoke_credential(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Credentials::<T>::contains_key(&who), Error::<T>::CredentialNotFound);
            Credentials::<T>::remove(&who);
            Self::deposit_event(Event::CredentialRevoked { who });
            Ok(())
        }
    }

    // 内部公共逻辑：执行凭证创建
    impl<T: Config> Pallet<T> {
        fn do_issue(who: &T::AccountId, remark_vec: Vec<u8>) -> DispatchResult {
            let bounded_remark: BoundedVec<u8, T::MaxRemarkLen> = 
                remark_vec.try_into().map_err(|_| Error::<T>::RemarkTooLong)?;

            let mut public_key = [0u8; 32];
            let encoded_id = who.encode();
            if encoded_id.len() >= 32 {
                public_key.copy_from_slice(&encoded_id[..32]);
            }
            let account_info = frame_system::Pallet::<T>::account(who);

            let new_credential = Credential {
                remark: bounded_remark,
                public_key,
                nonce: account_info.nonce,
            };

            Credentials::<T>::insert(who, new_credential);
            Ok(())
        }
    }
}