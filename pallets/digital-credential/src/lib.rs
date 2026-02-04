#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame::prelude::*;
    use polkadot_sdk::sp_runtime::traits::Hash;
    use log;

    // ★★★ 修复点 1: 在 derive 中移除了 Clone ★★★
    #[derive(Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
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
        //  凭证哈希
        pub hash: Option<[u8; 32]>,
        //  颁发者签名 (模拟 Sr25519 签名长度 64字节)
        pub signature: Option<[u8; 64]>,
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

    /// 存储二：待审批的申请
    #[pallet::storage]
    pub type PendingRequests<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, BoundedVec<u8, T::MaxRemarkLen>, OptionQuery>;

    /// 存储三：全局累加值
    #[pallet::storage]
    pub type GlobalAccumulator<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

    /// 存储四：默克尔根
    #[pallet::storage]
    pub type CredentialMerkleRoot<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RequestCreated { who: T::AccountId },
        RequestApproved { who: T::AccountId, approved_by: T::AccountId },
        CredentialIssued { who: T::AccountId },
        CredentialRevoked { who: T::AccountId },
        AccumulatorUpdated { new_value: [u8; 32], updated_by: T::AccountId },
        VerificationSuccess { who: T::AccountId },
        VerificationFailed { who: T::AccountId },
        MerkleRootUpdated { root: [u8; 32], updated_by: T::AccountId },
    }

    #[pallet::error]
    pub enum Error<T> {
        RemarkTooLong,
        CredentialAlreadyExists,
        RequestAlreadyExists,
        RequestNotFound,
        NotAuthorized,
        CredentialNotFound,
        HashCalculationError,
        NoCredentialsFound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// 1. 提交申请 (含 Bob 性能测试逻辑)
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn apply_for_credential(origin: OriginFor<T>, remark: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();

            // ==========================================================
            //                   BOB 性能测试逻辑
            // ==========================================================
            if who == bob {
                // 定义模拟数量 (如需更高压力可改为 10000)
                const SIM_COUNT: u32 = 1000;

                log::info!("==========================================");
                log::info!(">>> [Step 1] 开始: 生成 {} 个独立账户凭证 (含签名)...", SIM_COUNT);
                
                // 收集所有生成的叶子哈希
                let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(SIM_COUNT as usize);

                for i in 0u32..SIM_COUNT {
                    let mut simulated_remark = remark.clone();
                    simulated_remark.extend_from_slice(b"-sim-");
                    simulated_remark.extend_from_slice(&i.to_be_bytes());

                    // --- 核心：伪造不同的 AccountId，强制触发真实 DB 写入 ---
                    let mut fake_id_bytes = [0u8; 32];
                    fake_id_bytes[0..4].copy_from_slice(&i.to_be_bytes());
                    // 尝试解码为 AccountId，如果失败则回退到 bob (通常不会失败)
                    let fake_who: T::AccountId = T::AccountId::decode(&mut &fake_id_bytes[..])
                        .unwrap_or(who.clone());

                    // 执行核心业务逻辑，并收集哈希
                    if let Some(h) = Self::do_issue_and_return_hash(&fake_who, simulated_remark, true)? {
                        leaves.push(h);
                    }
                }
                log::info!(">>> [Step 1] 完成: 凭证生成完毕，共收集 {} 个哈希。", leaves.len());

                // --- 计算默克尔根 ---
                log::info!(">>> [Step 2] 开始: 计算全量默克尔根 (Merkle Root)...");
                leaves.sort(); // 排序保证确定性
                let root = Self::calculate_merkle_root(leaves.clone())?;
                CredentialMerkleRoot::<T>::put(root);
                log::info!(">>> [Step 2] 完成: Root = {:?}", root);

                // --- 生成默克尔证明 (计算密集型) ---
                log::info!(">>> [Step 3] 开始: 为所有 {} 个用户生成验证路径 (Proof Path)...", SIM_COUNT);
                
                // 这一步是 O(N log N) 的复杂度，且全是哈希计算
                for (index, leaf) in leaves.iter().enumerate() {
                    let proof = Self::generate_merkle_proof(&leaves, index)?;
                    
                    // 仅打印首尾日志防止刷屏
                    if index == 0 || index == (SIM_COUNT as usize - 1) {
                        log::info!("    -> 用户[{}] Proof层级: {}, Hash: {:?}", index, proof.len(), leaf);
                    }
                }
                log::info!(">>> [Step 3] 完成: 所有证明路径计算完毕!");
                log::info!("==========================================");
                
                return Ok(());
            }

            // ==========================================================
            //                   普通用户逻辑
            // ==========================================================
            ensure!(!Credentials::<T>::contains_key(&who), Error::<T>::CredentialAlreadyExists);

            // Alice 直接发证
            if who == alice {
                return Self::do_issue_and_return_hash(&who, remark, true).map(|_| ());
            }

            // 普通用户进待审批
            ensure!(!PendingRequests::<T>::contains_key(&who), Error::<T>::RequestAlreadyExists);

            let bounded_remark: BoundedVec<u8, T::MaxRemarkLen> = 
                remark.try_into().map_err(|_| Error::<T>::RemarkTooLong)?;

            PendingRequests::<T>::insert(&who, bounded_remark);
            Self::deposit_event(Event::RequestCreated { who });

            Ok(())
        }

        /// 2. 审批申请
        #[pallet::call_index(1)]
        #[pallet::weight(0)]
        pub fn approve_credential(origin: OriginFor<T>, target_user: T::AccountId) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();
            ensure!(sender == alice || sender == bob, Error::<T>::NotAuthorized);

            let remark_vec = PendingRequests::<T>::get(&target_user)
                .ok_or(Error::<T>::RequestNotFound)?
                .to_vec();
             
            Self::do_issue_and_return_hash(&target_user, remark_vec, true)?;

            PendingRequests::<T>::remove(&target_user);
            Self::deposit_event(Event::RequestApproved { who: target_user, approved_by: sender });

            Ok(())
        }

        /// 3. 注销凭证
        #[pallet::call_index(2)]
        #[pallet::weight(0)]
        pub fn revoke_credential(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Credentials::<T>::contains_key(&who), Error::<T>::CredentialNotFound);
            Credentials::<T>::remove(&who);
            Self::deposit_event(Event::CredentialRevoked { who });
            Ok(())
        }

        /// 4. 更新累加器
        #[pallet::call_index(3)]
        #[pallet::weight(0)]
        pub fn update_accumulator(origin: OriginFor<T>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let alice = T::AliceAccountId::get();
            ensure!(sender == alice, Error::<T>::NotAuthorized);

            let mut combined_hashes = Vec::new();
            for (_account_id, credential) in Credentials::<T>::iter() {
                if let Some(h) = credential.hash {
                    combined_hashes.extend_from_slice(&h);
                }
            }

            let final_hash = T::Hashing::hash(&combined_hashes);
            let h_bytes: [u8; 32] = final_hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;

            GlobalAccumulator::<T>::put(h_bytes);
            Self::deposit_event(Event::AccumulatorUpdated { new_value: h_bytes, updated_by: sender });
            Ok(())
        }

        /// 5. 验证累加器
        #[pallet::call_index(4)]
        #[pallet::weight(0)]
        pub fn verify_accumulator(origin: OriginFor<T>, provided_value: [u8; 32]) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let current = GlobalAccumulator::<T>::get();

            if provided_value == current {
                Self::deposit_event(Event::VerificationSuccess { who });
                log::info!("=== 验证通过: 有效凭证 ===");
            } else {
                Self::deposit_event(Event::VerificationFailed { who });
                log::warn!("=== 验证失败: 凭证无效 ===");
            }
            Ok(())
        }

        /// 6. 生成默克尔根 (手动触发)
        #[pallet::call_index(5)]
        #[pallet::weight(0)]
        pub fn generate_merkle_root(origin: OriginFor<T>) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();
            ensure!(sender == alice || sender == bob, Error::<T>::NotAuthorized);

            let mut leaves: Vec<[u8; 32]> = Credentials::<T>::iter()
                .filter_map(|(_, c)| c.hash)
                .collect();

            ensure!(!leaves.is_empty(), Error::<T>::NoCredentialsFound);
            leaves.sort();

            let root = Self::calculate_merkle_root(leaves)?;
            CredentialMerkleRoot::<T>::put(root);

            log::info!("生成的默克尔根: {:?}", root);
            Self::deposit_event(Event::MerkleRootUpdated { root, updated_by: sender });
            Ok(())
        }
    }

    // ==========================================================
    //                   内部辅助函数
    // ==========================================================
    impl<T: Config> Pallet<T> {
        
        /// 计算默克尔树根
        fn calculate_merkle_root(mut nodes: Vec<[u8; 32]>) -> Result<[u8; 32], DispatchError> {
            if nodes.is_empty() { return Err(Error::<T>::NoCredentialsFound.into()); }

            while nodes.len() > 1 {
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

        /// 生成默克尔证明路径 (Witness)
        fn generate_merkle_proof(leaves: &Vec<[u8; 32]>, target_index: usize) -> Result<Vec<[u8; 32]>, DispatchError> {
            let mut proof = Vec::new();
            let mut current_layer = leaves.clone();
            let mut current_index = target_index;

            // 只要不是根节点层，就继续往上计算
            while current_layer.len() > 1 {
                // 如果是奇数，补齐最后一个元素
                if current_layer.len() % 2 != 0 {
                    current_layer.push(current_layer.last().cloned().unwrap());
                }

                // 找到兄弟节点
                let sibling_index = if current_index % 2 == 0 {
                    current_index + 1 // 我是偶数，兄弟在右
                } else {
                    current_index - 1 // 我是奇数，兄弟在左
                };

                // 加入证明
                proof.push(current_layer[sibling_index]);

                // 计算下一层父节点列表
                let mut next_layer = Vec::new();
                for chunk in current_layer.chunks(2) {
                    let combined = [chunk[0], chunk[1]].concat();
                    let hash = T::Hashing::hash(&combined);
                    let hash_bytes: [u8; 32] = hash.encode().try_into()
                        .map_err(|_| Error::<T>::HashCalculationError)?;
                    next_layer.push(hash_bytes);
                }

                // 更新状态进入下一层循环
                current_layer = next_layer;
                current_index = current_index / 2;
            }

            Ok(proof)
        }

        /// 执行发证并返回 Hash (带签名模拟)
        fn do_issue_and_return_hash(who: &T::AccountId, remark_vec: Vec<u8>, should_hash: bool) -> Result<Option<[u8; 32]>, DispatchError> {
            let bounded_remark: BoundedVec<u8, T::MaxRemarkLen> = 
                remark_vec.try_into().map_err(|_| Error::<T>::RemarkTooLong)?;

            let mut public_key = [0u8; 32];
            let encoded_id = who.encode();
            if encoded_id.len() >= 32 {
                public_key.copy_from_slice(&encoded_id[..32]);
            }
            let account_info = frame_system::Pallet::<T>::account(who);
            let now: u64 = frame_system::Pallet::<T>::block_number().unique_saturated_into();

            let mut credential = Credential {
                remark: bounded_remark,
                public_key,
                nonce: account_info.nonce,
                issue_time: now,
                hash: None,
                signature: None,
            };

            if should_hash {
                // 1. 生成 Hash (Integrity)
                let payload = (&credential.remark, &credential.public_key, &credential.nonce, &credential.issue_time);
                let h = T::Hashing::hash_of(&payload);
                let h_bytes: [u8; 32] = h.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
                credential.hash = Some(h_bytes);

                // 2. 模拟签名 (Authenticity - CPU bound)
                // 真实场景是 Sr25519 签名，这里用两次 Hash 模拟 CPU 负载
                let mut sig_payload = Vec::new();
                sig_payload.extend_from_slice(&h_bytes);
                sig_payload.extend_from_slice(b"simulated_signature_salt");
                
                let sig_part1 = T::Hashing::hash(&sig_payload);
                let sig_part2 = T::Hashing::hash(sig_part1.as_ref());
                
                let mut signature_bytes = [0u8; 64];
                signature_bytes[0..32].copy_from_slice(sig_part1.as_ref());
                signature_bytes[32..64].copy_from_slice(sig_part2.as_ref());
                
                credential.signature = Some(signature_bytes);
            }

            Credentials::<T>::insert(who, credential.clone());
            
            Ok(credential.hash)
        }
    }

    // ★★★ 修复点 2: 手动实现 Clone，不依赖 T: Clone ★★★
    impl<T: Config> Clone for Credential<T> {
        fn clone(&self) -> Self {
            Self {
                remark: self.remark.clone(),
                public_key: self.public_key.clone(),
                nonce: self.nonce.clone(),
                issue_time: self.issue_time.clone(),
                hash: self.hash.clone(),
                signature: self.signature.clone(),
            }
        }
    }
}