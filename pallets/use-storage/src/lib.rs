#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[frame::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame::prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching runtime event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    // Can stringify event types to metadata.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        SetClass(u32),
        SetStudentInfo(u32, u128),
        SetDormInfo(u32, u32, u32),
    }

    #[pallet::error]
    pub enum Error<T> {
        NoneValue,
        StorageOverflow,
    }

    #[pallet::storage]
    #[pallet::getter(fn my_class)]
    // pub type MyStorage<T> = StorageValue<_, u32, ValueQuery>;
    pub type Class<T: Config> = StorageValue<_, u32, ValueQuery>;

    // use storageMap store (student number -> student name).
    #[pallet::storage]
    #[pallet::getter(fn students_info)]
    pub type StudentsInfo<T: Config> = StorageMap<_, Blake2_128Concat, u32, u128, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn dorm_info)]
    pub type DormInfo<T: Config> =StorageDoubleMap<
      _, 
      Blake2_128Concat, 
      u32,   //寝室号
      Blake2_128Concat, 
      u32,   //床号
      u32,   //学号
      ValueQuery
    >;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // Dispatchable functions will be added here

        //设置这个操作的有多少权重
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn set_class_info(origin: OriginFor<T>, class: u32)  -> DispatchResultWithPostInfo {  
            //操作者权限判断：只有root账户才能设置班级信息
            ensure_root(origin)?;
            
            // 设置班级信息
            // 因为在上面storage部分我们声明了Class这个type是StorageValue这个类型
            // StorageValue类型Rust里面初始化了很多方法，其中put()就是一个默认方法
            Class::<T>::put(class);

            //触发对应事件（具体逻辑在event篇中讲解）
            // Self::deposit_event(Event::SetClass(class)); 
            
            //函数运行成功后固定写法
            Ok(().into())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(0)]
        pub fn set_student_info(  
            origin: OriginFor<T>,  
            student_number: u32,  
            student_name: u128,
        ) -> DispatchResultWithPostInfo {  
            ensure_signed(origin)?;

            StudentsInfo::<T>::insert(&student_number, &student_name);

            // Self::deposit_event(Event::SetStudentInfo(    
            //     student_number,     
            //     student_name)
            // );
            
            Ok(().into())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(0)]
        pub fn set_dorm_info(  
            origin: OriginFor<T>,  
            dorm_number: u32,  
            bed_number: u32,  
            student_number: u32,
        ) -> DispatchResultWithPostInfo {  
            ensure_signed(origin)?;
            
            DormInfo::<T>::insert(&dorm_number, &bed_number, student_number);

            // Self::deposit_event(Event::SetDormInfo(    
            //     dorm_number,     
            //     bed_number,     
            //     student_number));
                
            Ok(().into())
        }
    }
}
