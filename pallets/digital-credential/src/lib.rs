#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame::prelude::*;
    use polkadot_sdk::sp_runtime::traits::Hash;
    use log;

    #[derive(Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct Credential<T: Config> {
        pub remark: BoundedVec<u8, T::MaxRemarkLen>,
        pub public_key: [u8; 32],
        pub nonce: T::Nonce,
        pub issue_time: u64,
        pub hash: Option<[u8; 32]>,
        pub signature: Option<[u8; 64]>,
        pub org_id: u32,
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

    #[pallet::storage]
    pub type Credentials<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Credential<T>, OptionQuery>;

    #[pallet::storage]
    pub type PendingRequests<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, BoundedVec<u8, T::MaxRemarkLen>, OptionQuery>;

    /// 存储三：组织 ID -> 该组织的 MMR Root
    #[pallet::storage]
    pub type OrgMMRRoots<T: Config> = StorageMap<_, Blake2_128Concat, u32, [u8; 32], ValueQuery>;

    /// 存储四：组织 ID -> 该组织的 MMR Size (叶子总数)
    #[pallet::storage]
    pub type OrgMMRSizes<T: Config> = StorageMap<_, Blake2_128Concat, u32, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RequestCreated { who: T::AccountId },
        RequestApproved { who: T::AccountId, approved_by: T::AccountId },
        CredentialIssued { who: T::AccountId, org_id: u32 },
        CredentialRevoked { who: T::AccountId },
        VerificationSuccess { who: T::AccountId, org_id: u32 },
        VerificationFailed { who: T::AccountId, org_id: u32 },
        OrgRootUpdated { org_id: u32, root: [u8; 32], size: u64 },
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
        ProofVerificationFailed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn apply_for_credential(origin: OriginFor<T>, remark: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let alice = T::AliceAccountId::get();
            let bob = T::BobAccountId::get();

            // ==========================================================
            //           BOB 多组织 (Multi-Org) MMR 性能测试
            // ==========================================================
            if who == bob {
                const NUM_ORGS: u32 = 10;           
                const USERS_PER_ORG: u32 = 1000;    
                const VERIFY_PER_ORG: usize = 100;  
                const REVOKE_PER_ORG: usize = 100;  

                log::info!("==========================================");
                log::info!(">>> [Step 1] 开始: 为 {} 个组织各生成 {} 个凭证 (总量 {})...", NUM_ORGS, USERS_PER_ORG, NUM_ORGS * USERS_PER_ORG);
                
                let mut org_leaves: Vec<Vec<[u8; 32]>> = Vec::with_capacity(NUM_ORGS as usize);

                for org_id in 0..NUM_ORGS {
                    let mut current_org_leaves = Vec::with_capacity(USERS_PER_ORG as usize);
                    for i in 0..USERS_PER_ORG {
                        let mut simulated_remark = remark.clone();
                        simulated_remark.extend_from_slice(b"-org-");
                        simulated_remark.extend_from_slice(&org_id.to_be_bytes());
                        simulated_remark.extend_from_slice(b"-usr-");
                        simulated_remark.extend_from_slice(&i.to_be_bytes());

                        let mut fake_id_bytes = [0u8; 32];
                        fake_id_bytes[0..4].copy_from_slice(&org_id.to_be_bytes());
                        fake_id_bytes[4..8].copy_from_slice(&i.to_be_bytes());
                        let fake_who: T::AccountId = T::AccountId::decode(&mut &fake_id_bytes[..]).unwrap_or(who.clone());

                        if let Some(h) = Self::do_issue_and_return_hash(&fake_who, simulated_remark, org_id, true)? {
                            current_org_leaves.push(h);
                        }
                    }
                    org_leaves.push(current_org_leaves);
                }
                log::info!(">>> [Step 1] 完成: 数据准备就绪。");

                // --- Step 2: 构建所有组织的 MMR ---
                log::info!(">>> [Step 2] 开始: 构建 {} 个组织的 MMR (Append-only)...", NUM_ORGS);
                
                // 缓存所有组织的 Peaks，用于 Step 3 生成证明，避免重复计算
                let mut all_org_peaks: Vec<Vec<(u32, [u8; 32])>> = Vec::with_capacity(NUM_ORGS as usize);

                for (org_id_usize, leaves) in org_leaves.iter().enumerate() {
                    let mut peaks: Vec<(u32, [u8; 32])> = Vec::new();
                    // MMR 构建：逐个插入
                    for leaf in leaves {
                        Self::mmr_push(&mut peaks, *leaf)?;
                    }
                    
                    let root = Self::mmr_calculate_root(&peaks)?;
                    let size = leaves.len() as u64;
                    
                    OrgMMRRoots::<T>::insert(org_id_usize as u32, root);
                    OrgMMRSizes::<T>::insert(org_id_usize as u32, size);
                    
                    all_org_peaks.push(peaks);
                }
                log::info!(">>> [Step 2] 完成: 所有组织的 MMR Root & Size 已上链。");

                // --- Step 3: 预生成部分 MMR Proof 用于验证测试 ---
                log::info!(">>> [Step 3] 准备: 为跨组织验证预生成 MMR Proofs...");
                
                // 结构: (OrgId, Root, Size, Leaf, Proof, Index)
                let mut proofs_to_verify: Vec<(u32, [u8;32], u64, [u8;32], Vec<[u8;32]>, usize)> = Vec::new();

                for org_id in 0..NUM_ORGS {
                    let leaves = &org_leaves[org_id as usize];
                    let peaks = &all_org_peaks[org_id as usize];
                    let peak_hashes: Vec<[u8; 32]> = peaks.iter().map(|(_, h)| *h).collect();
                    
                    let root = OrgMMRRoots::<T>::get(org_id);
                    let size = OrgMMRSizes::<T>::get(org_id);

                    // 选取前 VERIFY_PER_ORG 个做验证
                    for index in 0..VERIFY_PER_ORG {
                        let proof = Self::mmr_generate_proof(leaves, index, &peak_hashes)?;
                        let leaf = leaves[index];
                        proofs_to_verify.push((org_id, root, size, leaf, proof, index));
                    }
                }
                log::info!(">>> [Step 3] 准备完成: 生成了 {} 个待验证 MMR Proof", proofs_to_verify.len());

                // --- Step 4: 跨组织验证测试 ---
                log::info!(">>> [Step 4] 开始: 模拟验证 {} 个凭证 (Multi-Org MMR Verification)...", proofs_to_verify.len());
                
                for (org_id, root, size, leaf, proof, index) in proofs_to_verify {
                    let is_valid = Self::mmr_verify_proof(leaf, proof, index, size, root)?;
                    if !is_valid {
                        log::error!("!!! 验证失败: Org {} Index {}", org_id, index);
                        return Err(Error::<T>::ProofVerificationFailed.into());
                    }
                }
                log::info!(">>> [Step 4] 完成: 所有凭证验证通过!");

                // ==========================================================
                // ★★★ Step 5: 跨组织撤销测试 (Rebuild & Update) ★★★
                // 模拟最坏情况：需要移除数据，导致 MMR 重构
                // ==========================================================
                log::info!("------------------------------------------");
                let total_revoked = NUM_ORGS as usize * REVOKE_PER_ORG;
                let remaining_per_org = USERS_PER_ORG as usize - REVOKE_PER_ORG;
                
                log::info!(">>> [Step 5] 开始: 10个组织并行撤销 (总计撤销 {}, 更新 {} 个 MMR 路径)...", total_revoked, NUM_ORGS as usize * remaining_per_org);

                for org_id in 0..NUM_ORGS {
                    let leaves = &mut org_leaves[org_id as usize];
                    
                    // [5.1] 模拟撤销
                    if leaves.len() > REVOKE_PER_ORG {
                        leaves.drain(0..REVOKE_PER_ORG);
                    }
                    
                    // [5.2] 重构 MMR 结构 (Re-Push)
                    // 虽然是重构，但 MMR Push 极其廉价
                    let mut new_peaks: Vec<(u32, [u8; 32])> = Vec::new();
                    for leaf in leaves.iter() {
                        Self::mmr_push(&mut new_peaks, *leaf)?;
                    }
                    
                    let new_root = Self::mmr_calculate_root(&new_peaks)?;
                    let new_size = leaves.len() as u64;
                    
                    OrgMMRRoots::<T>::insert(org_id, new_root);
                    OrgMMRSizes::<T>::insert(org_id, new_size);
                    
                    // [5.3] 更新该组织剩余 900 个用户的 Proof
                    let new_peak_hashes: Vec<[u8; 32]> = new_peaks.iter().map(|(_, h)| *h).collect();
                    
                    if org_id == 0 {
                        log::info!("    -> 正在处理 Org 0 的撤销与更新 (其他组织同理)...");
                    }

                    for index in 0..leaves.len() {
                        let _new_proof = Self::mmr_generate_proof(leaves, index, &new_peak_hashes)?;
                    }
                }

                log::info!(">>> [Step 5] 完成: 多组织 MMR 撤销与全量路径更新结束!");
                log::info!("==========================================");
                
                return Ok(());
            }

            // 普通用户逻辑
            ensure!(!Credentials::<T>::contains_key(&who), Error::<T>::CredentialAlreadyExists);
            if who == alice {
                return Self::do_issue_and_return_hash(&who, remark, 0, true).map(|_| ());
            }
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(0)]
        pub fn approve_credential(origin: OriginFor<T>, target_user: T::AccountId) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            // 简单处理：默认 Org 0
            let remark_vec = PendingRequests::<T>::get(&target_user).ok_or(Error::<T>::RequestNotFound)?.to_vec();
            Self::do_issue_and_return_hash(&target_user, remark_vec, 0, true)?;
            PendingRequests::<T>::remove(&target_user);
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(0)]
        pub fn revoke_credential(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Credentials::<T>::contains_key(&who), Error::<T>::CredentialNotFound);
            Credentials::<T>::remove(&who);
            Ok(())
        }
        
        #[pallet::call_index(3)]
        #[pallet::weight(0)]
        pub fn update_accumulator(_origin: OriginFor<T>) -> DispatchResult { Ok(()) }
        
        #[pallet::call_index(4)]
        #[pallet::weight(0)]
        pub fn verify_accumulator(_origin: OriginFor<T>, _val: [u8;32]) -> DispatchResult { Ok(()) }
    }

    // ==========================================================
    //                 MMR 核心逻辑实现
    // ==========================================================
    impl<T: Config> Pallet<T> {
        
        fn mmr_push(peaks: &mut Vec<(u32, [u8; 32])>, new_leaf: [u8; 32]) -> Result<(), DispatchError> {
            let mut current_hash = new_leaf;
            let mut current_height = 0;
            loop {
                // 修复：使用 _ 忽略未使用的 prev_hash
                if let Some((prev_height, _)) = peaks.last() {
                    if *prev_height == current_height {
                        let (_, left_hash) = peaks.pop().ok_or(Error::<T>::HashCalculationError)?;
                        let right_hash = current_hash;
                        let combined = [left_hash, right_hash].concat();
                        let parent_hash = T::Hashing::hash(&combined);
                        current_hash = parent_hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
                        current_height += 1;
                        continue;
                    }
                }
                peaks.push((current_height, current_hash));
                break;
            }
            Ok(())
        }

        fn mmr_calculate_root(peaks: &Vec<(u32, [u8; 32])>) -> Result<[u8; 32], DispatchError> {
            if peaks.is_empty() { return Err(Error::<T>::NoCredentialsFound.into()); }
            let mut current_root_hash = peaks[0].1;
            for i in 1..peaks.len() {
                let next_peak_hash = peaks[i].1;
                let combined = [current_root_hash, next_peak_hash].concat(); 
                let hash = T::Hashing::hash(&combined);
                current_root_hash = hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
            }
            Ok(current_root_hash)
        }

        fn mmr_generate_proof(
            all_leaves: &Vec<[u8; 32]>, 
            target_index: usize, 
            peak_hashes: &Vec<[u8; 32]>
        ) -> Result<Vec<[u8; 32]>, DispatchError> {
            let mut proof = Vec::new();

            let mut remaining_leaves = all_leaves.as_slice();
            let mut current_offset = 0;
            let mut target_peak_idx = 0;
            let mut target_mountain_leaves: &[ [u8;32] ] = &[];
            let mut size = all_leaves.len() as u64; // 修复类型歧义
            let mut peak_itr = 0;
            
            while size > 0 {
                let mountain_size: u64 = 1 << (u64::BITS - size.leading_zeros() - 1);
                
                if (target_index as u64) < (current_offset + mountain_size) {
                    target_mountain_leaves = &remaining_leaves[0..mountain_size as usize];
                    target_peak_idx = peak_itr;
                    break; 
                }
                current_offset += mountain_size;
                remaining_leaves = &remaining_leaves[mountain_size as usize..];
                size -= mountain_size;
                peak_itr += 1;
            }

            let relative_index = target_index - current_offset as usize;
            let local_path = Self::generate_perfect_tree_proof(target_mountain_leaves, relative_index)?;
            proof.extend(local_path);

            for (i, p_hash) in peak_hashes.iter().enumerate() {
                if i != target_peak_idx {
                    proof.push(*p_hash);
                }
            }
            Ok(proof)
        }

        fn mmr_verify_proof(
            leaf: [u8; 32],
            mut proof: Vec<[u8; 32]>,
            target_index: usize,
            total_size: u64,
            expected_root: [u8; 32]
        ) -> Result<bool, DispatchError> {
            let mut size = total_size;
            let mut current_offset = 0;
            let mut target_peak_height = 0;
            let mut target_peak_index_in_peaks = 0;
            let mut peak_itr = 0;

            while size > 0 {
                let mountain_size: u64 = 1 << (u64::BITS - size.leading_zeros() - 1);
                // 修复：使用 trailing_zeros
                let height = mountain_size.trailing_zeros();
                
                if (target_index as u64) < (current_offset + mountain_size) {
                    target_peak_height = height;
                    target_peak_index_in_peaks = peak_itr;
                    break;
                }
                current_offset += mountain_size;
                size -= mountain_size;
                peak_itr += 1;
            }

            let mut current_hash = leaf;
            let mut relative_index = target_index - current_offset as usize;

            let local_siblings: Vec<[u8; 32]> = proof.drain(0..target_peak_height as usize).collect();

            for sibling in local_siblings {
                let combined = if relative_index % 2 == 0 {
                    [current_hash, sibling].concat()
                } else {
                    [sibling, current_hash].concat()
                };
                let hash = T::Hashing::hash(&combined);
                current_hash = hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
                relative_index /= 2;
            }

            let calculated_local_peak = current_hash;
            proof.insert(target_peak_index_in_peaks, calculated_local_peak);
            let peaks = proof;

            let mut current_root = peaks[0];
            for i in 1..peaks.len() {
                let next = peaks[i];
                let combined = [current_root, next].concat();
                let hash = T::Hashing::hash(&combined);
                current_root = hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
            }

            Ok(current_root == expected_root)
        }

        fn generate_perfect_tree_proof(leaves: &[ [u8;32] ], target_index: usize) -> Result<Vec<[u8; 32]>, DispatchError> {
            let mut proof = Vec::new();
            let mut current_layer = leaves.to_vec();
            let mut idx = target_index;

            while current_layer.len() > 1 {
                let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                proof.push(current_layer[sibling_idx]);

                let mut next_layer = Vec::new();
                for chunk in current_layer.chunks(2) {
                    let combined = [chunk[0], chunk[1]].concat();
                    let hash = T::Hashing::hash(&combined);
                    let h_bytes: [u8; 32] = hash.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
                    next_layer.push(h_bytes);
                }
                current_layer = next_layer;
                idx /= 2;
            }
            Ok(proof)
        }

        fn do_issue_and_return_hash(who: &T::AccountId, remark_vec: Vec<u8>, org_id: u32, should_hash: bool) -> Result<Option<[u8; 32]>, DispatchError> {
            let bounded_remark: BoundedVec<u8, T::MaxRemarkLen> = 
                remark_vec.try_into().map_err(|_| Error::<T>::RemarkTooLong)?;
            let mut public_key = [0u8; 32];
            let encoded_id = who.encode();
            if encoded_id.len() >= 32 { public_key.copy_from_slice(&encoded_id[..32]); }
            let account_info = frame_system::Pallet::<T>::account(who);
            let now: u64 = frame_system::Pallet::<T>::block_number().unique_saturated_into();

            let mut credential = Credential {
                remark: bounded_remark,
                public_key,
                nonce: account_info.nonce,
                issue_time: now,
                hash: None,
                signature: None,
                org_id,
            };
            if should_hash {
                let payload = (&credential.remark, &credential.public_key, &credential.nonce, &credential.issue_time, &credential.org_id);
                let h = T::Hashing::hash_of(&payload);
                let h_bytes: [u8; 32] = h.encode().try_into().map_err(|_| Error::<T>::HashCalculationError)?;
                credential.hash = Some(h_bytes);
                let mut sig_payload = Vec::new();
                sig_payload.extend_from_slice(&h_bytes);
                sig_payload.extend_from_slice(b"salt");
                let sig_p1 = T::Hashing::hash(&sig_payload);
                let sig_p2 = T::Hashing::hash(sig_p1.as_ref());
                let mut sig_bytes = [0u8; 64];
                sig_bytes[0..32].copy_from_slice(sig_p1.as_ref());
                sig_bytes[32..64].copy_from_slice(sig_p2.as_ref());
                credential.signature = Some(sig_bytes);
            }
            Credentials::<T>::insert(who, credential.clone());
            Ok(credential.hash)
        }
    }

    impl<T: Config> Clone for Credential<T> {
        fn clone(&self) -> Self {
            Self {
                remark: self.remark.clone(),
                public_key: self.public_key.clone(),
                nonce: self.nonce.clone(),
                issue_time: self.issue_time.clone(),
                hash: self.hash.clone(),
                signature: self.signature.clone(),
                org_id: self.org_id,
            }
        }
    }
}