#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame::prelude::*;

    // --- 调整后的导入路径 ---
    // use polkadot_sdk::frame_support::traits::Time;
    use polkadot_sdk::sp_runtime::traits::Hash;
    // use polkadot_sdk::pallet_timestamp;
    // use polkadot_sdk::frame_system::pallet_prelude::*;
    use log;


    #[derive(Clone, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    // #[derive(Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct Credential<T: Config> {
        //  账户信息备注
        pub remark: BoundedVec<u8, T::MaxRemarkLen>,
        //  账户公钥
        pub public_key: [u8; 32],
        //  账户交易次数
        pub nonce: T::Nonce,
        //  生成时间
        pub issue_time: u64,
        //  凭证哈希 (初始为 None，审批后存入)
        pub hash: Option<[u8; 32]>,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // 继承 pallet_timestamp::Config 以获取时间
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type MaxRemarkLen: Get<u32>;
        #[pallet::constant]
        type AliceAccountId: Get<Self::AccountId>;
        #[pallet::constant]
        type BobAccountId: Get<Self::AccountId>;

        // type BlockNumber: Parameter
        // + Member
        // + AtLeast32BitUnsigned
        // + Default
        // + Copy
        // + MaxEncodedLen;
    }

    /// 存储一：正式的凭证
    #[pallet::storage]
    pub type Credentials<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Credential<T>, OptionQuery>;

    /// 存储二：待审批的申请 [账户ID -> 备注内容]
    #[pallet::storage]
    pub type PendingRequests<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, BoundedVec<u8, T::MaxRemarkLen>, OptionQuery>;

    // 存储3：全局累加值
    #[pallet::storage]
    pub type GlobalAccumulator<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

    // 存储4：默克尔根
    #[pallet::storage]
    pub type CredentialMerkleRoot<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

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
        // 累加器更新
        AccumulatorUpdated { new_value: [u8; 32], updated_by: T::AccountId },
         // 校验成功的事件
        VerificationSuccess { who: T::AccountId },
        // 校验失败的事件
        VerificationFailed { who: T::AccountId },
        // 默克尔根更新事件
        MerkleRootUpdated { root: [u8; 32], updated_by: T::AccountId },
    }

    #[pallet::error]
    pub enum Error<T> {
        RemarkTooLong,
        CredentialAlreadyExists,
        RequestAlreadyExists,
        RequestNotFound,
        NotAuthorized,  // 不是 Alice 或 Bob，无权审批
        CredentialNotFound,
        HashCalculationError,
        NoCredentialsFound,  // 没有可用的哈希
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
                return Self::do_issue(&who, remark, true);
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
            log::info!(">>>>>> [DEBUG] approve_credential 函数开始运行了！");
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
            Self::do_issue(&target_user, remark_vec, true)?;

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

        // --- 新增功能：更新累加器 (仅限 Alice 调用) ---
        #[pallet::call_index(3)]
        #[pallet::weight(0)]
        pub fn update_accumulator(origin: OriginFor<T>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // 权限校验：仅限 Alice
            let alice = T::AliceAccountId::get();
            ensure!(sender == alice, Error::<T>::NotAuthorized);

            // 逻辑：遍历所有凭证，将所有存在 hash 字段的值拼接后计算一个新的哈希
            let mut combined_hashes = Vec::new();
            
            // 遍历存储 map
            for (_account_id, credential) in Credentials::<T>::iter() {
                if let Some(h) = credential.hash {
                    combined_hashes.extend_from_slice(&h);
                }
            }

            // 计算最终累加值
            let final_hash = T::Hashing::hash(&combined_hashes);
            let h_bytes: [u8; 32] = final_hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;

            // 存储到链上
            GlobalAccumulator::<T>::put(h_bytes);

            // 发送事件
            Self::deposit_event(Event::AccumulatorUpdated { 
                new_value: h_bytes, 
                updated_by: sender 
            });

            Ok(())
        }

        // --- 新增功能：验证累加器 ---
        #[pallet::call_index(4)]
        #[pallet::weight(0)]
        pub fn verify_accumulator(origin: OriginFor<T>, provided_value: [u8; 32]) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // 获取链上最新的累加器值
            let current_accumulator = GlobalAccumulator::<T>::get();

            // 比较并发送对应的事件
            if provided_value == current_accumulator {
                Self::deposit_event(Event::VerificationSuccess { who });
                // 如果相等，在节点控制台打印
                log::info!("==========================================");
                log::info!("验证通过，是有效凭证!");
                log::info!("==========================================");
            } else {
                Self::deposit_event(Event::VerificationFailed { who });
                log::warn!("==========================================");
                log::warn!("验证失败，凭证已失效!");
                log::warn!("链上当前值: {:?}", current_accumulator);
                log::warn!("==========================================");
            }

            Ok(())
        }

        // --- 新增：生成默克尔树根 (仅限 Alice 或 Bob) ---
        #[pallet::call_index(5)]
        #[pallet::weight(0)]
        pub fn generate_merkle_root(origin: OriginFor<T>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // 权限校验
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();
            ensure!(sender == alice || sender == bob, Error::<T>::NotAuthorized);

            // 1. 收集所有已存在的凭证哈希作为叶子节点
            let mut leaves: Vec<[u8; 32]> = Credentials::<T>::iter()
                .filter_map(|(_, c)| c.hash)
                .collect();

            ensure!(!leaves.is_empty(), Error::<T>::NoCredentialsFound);

            // 2. 为了保证默克尔根的一致性，对叶子节点进行排序
            leaves.sort();

            // 3. 计算默克尔根
            let root = Self::calculate_merkle_root(leaves)?;

            // 4. 存储到链上
            CredentialMerkleRoot::<T>::put(root);

            // 5. 打印并发送事件
            log::info!("生成的默克尔根: {:?}", root);
            Self::deposit_event(Event::MerkleRootUpdated { 
                root, 
                updated_by: sender 
            });

            Ok(())
        }
    }

    // 内部公共逻辑：执行凭证创建
    impl<T: Config> Pallet<T> {
        // --- 新增：计算默克尔根的内部逻辑 ---
        fn calculate_merkle_root(mut nodes: Vec<[u8; 32]>) -> Result<[u8; 32], DispatchError> {
            if nodes.is_empty() {
                return Err(Error::<T>::NoCredentialsFound.into());
            }

            // 循环处理，直到只剩一个节点（根）
            while nodes.len() > 1 {
                // 如果节点数是奇数，复制最后一个节点以凑成偶数（标准默克尔树做法）
                if nodes.len() % 2 != 0 {
                    nodes.push(nodes.last().cloned().unwrap());
                }

                let mut next_level = Vec::new();
                for chunk in nodes.chunks(2) {
                    let combined = [chunk[0], chunk[1]].concat();
                    let hash = T::Hashing::hash(&combined);
                    let hash_bytes: [u8; 32] = hash.encode().try_into()
                        .map_err(|_| Error::<T>::HashCalculationError)?;
                    next_level.push(hash_bytes);
                }
                nodes = next_level;
            }

            Ok(nodes[0])
        }

        // 新增参数 should_hash 控制是否立即生成哈希
        fn do_issue(who: &T::AccountId, remark_vec: Vec<u8>, should_hash: bool) -> DispatchResult {
            // log::info!("【性能测试】开始生成凭证逻辑...");
            // polkadot_sdk::sp_runtime::print("★★★ [Time Test] Start generating credential...");
            // log::error!(target: "TIME_TEST", ">>> [START] 凭证生成开始");
            // log::error!(target: "runtime", ">>>>>> [PERF_START] <<<<<<");
            log::info!("==========================================");
            log::info!("[START] 凭证生成开始");
            log::info!("==========================================");

            let bounded_remark: BoundedVec<u8, T::MaxRemarkLen> = 
                remark_vec.try_into().map_err(|_| Error::<T>::RemarkTooLong)?;

            let mut public_key = [0u8; 32];
            let encoded_id = who.encode();
            if encoded_id.len() >= 32 {
                public_key.copy_from_slice(&encoded_id[..32]);
            }
            let account_info = frame_system::Pallet::<T>::account(who);
            
            // 自动填充字段一：获取链上当前时间
            let now: u64 = frame_system::Pallet::<T>::block_number().unique_saturated_into();

            let mut credential = Credential {
                remark: bounded_remark,
                public_key,
                nonce: account_info.nonce,
                issue_time: now,
                hash: None, // 初始为空
            };

            // 自动填充字段二：根据逻辑生成哈希
            if should_hash {
                // 将四个字段组合在一起进行编码
                let payload = (
                    &credential.remark,
                    &credential.public_key,
                    &credential.nonce,
                    &credential.issue_time,
                );
                
                // 使用 T::Hashing (通常是 Blake2-256) 计算哈希
                let h = T::Hashing::hash_of(&payload);
                let h_bytes: [u8; 32] = h.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
                credential.hash = Some(h_bytes);
            }

            Credentials::<T>::insert(who, credential);

            // log::info!("【性能测试】凭证生成完成。");
            // polkadot_sdk::sp_runtime::print("★★★ [Time Test] Credential generated successfully.");
            // log::error!(target: "TIME_TEST", ">>> [END] 凭证生成结束");
            // log::error!(target: "runtime", ">>>>>> [PERF_END] <<<<<<");
            log::info!("==========================================");
            log::info!("[END] 凭证生成结束");
            log::info!("==========================================");
            Ok(())
        }
    }
}